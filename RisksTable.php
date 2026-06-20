<?php

declare(strict_types=1);

namespace App\Model\Table;

use AccessControl\SectionResourceInterface;
use AdvancedFilters\Lib\Configuration\FilterConfigurationBuilder;
use AdvancedFilters\Lib\SeedCollection;
use Api\Model\Behavior\ApiBehavior;
use App\Form\Risks\RiskClassificationsWidget;
use App\Model\Behavior\ReviewsBehavior;
use App\Model\Behavior\RiskBehavior;
use App\Model\Behavior\RiskClassificationBehavior;
use App\Model\Traits\ListTrait;
use App\Model\Traits\OptionalBehaviorTrait;
use App\Model\Traits\SectionTrait;
use App\Model\Traits\TraverseTrait;
use ArrayObject;
use Cake\Core\Plugin;
use Cake\Datasource\FactoryLocator;
use Cake\Event\EventInterface;
use Cake\I18n\Date;
use Cake\ORM\Entity;
use Cake\ORM\Locator\LocatorAwareTrait;
use Cake\ORM\Query;
use Cake\ORM\RulesChecker;
use Cake\ORM\Table;
use Cake\Utility\Inflector;
use Cake\Validation\Validator;
use DynamicStatus\Lib\Configuration\StatusConfigurationBuilder;
use FieldData\Control\OptionsParser;
use FieldData\Form\FormAwareTrait;
use FieldData\Form\FormInterface;
use FieldData\Lib\Collection;
use FormOrganization\FormOrganizer;
use FormOrganization\FormOrganizer\FieldDataWidget;
use FormOrganization\FormOrganizer\GroupWidget;
use FormOrganization\FormOrganizerWidget;
use ImportTool\Lib\ImportTool;
use IntegrityCheck\IntegrityCheckCollectionInterface;
use IntegrityCheck\Model\Table\IntegrityCheckCollectionTrait;
use NotificationSystem\Model\Table\NotificationSystemItemsTable;
use Reports\Model\Table\ReportBlockChartSettingsTable;
use Reports\Model\Table\ReportTemplatesTable;
use SwaggerBake\Lib\Model\ModelDecorator;
use SwaggerBake\Lib\OpenApi\Schema;
use UserFields\Lib\UserFields;

class RisksTable extends Table implements SectionResourceInterface, IntegrityCheckCollectionInterface
{
    use SectionTrait;
    use OptionalBehaviorTrait;
    use TraverseTrait;
    use ListTrait;
    use FormAwareTrait;
    use LocatorAwareTrait;
    use IntegrityCheckCollectionTrait;

    public const MITIGATION_STRATEGY_ACCEPT = RiskBehavior::MITIGATION_STRATEGY_ACCEPT;
    public const MITIGATION_STRATEGY_AVOID = RiskBehavior::MITIGATION_STRATEGY_AVOID;
    public const MITIGATION_STRATEGY_MITIGATE = RiskBehavior::MITIGATION_STRATEGY_MITIGATE;
    public const MITIGATION_STRATEGY_TRANSFER = RiskBehavior::MITIGATION_STRATEGY_TRANSFER;

    public static function mitigationStrategies(): array
    {
        return RiskBehavior::mitigationStrategies();
    }

    /**
     * @inheritDoc
     */
    public function implementedEvents(): array
    {
        return parent::implementedEvents() +
            [
                'FieldData.buildConfig' => 'buildFieldData',
                'Form.buildContent' => 'buildForm',
                'DynamicStatus.buildConfig' => ['callable' => 'buildDynamicStatusConfig', 'priority' => 20],
                'AdvancedFilters.buildConfig' => ['callable' => 'buildAdvancedFilters', 'priority' => 20],
                'AdvancedFilters.beforeFind' => ['callable' => 'findAdvancedFilter', 'priority' => 20],
                'Reports.buildConfig' => 'buildReportsConfig',
                'ImportTool.buildConfig' => 'buildImportToolConfig',
                'SectionInfo.buildConfig' => 'buildSectionInfoConfig',
                'Api.buildConfig' => 'buildApiConfig',
                'Api.buildNewConfig' => 'buildNewApiConfig',
                'FormOrganization.buildOrganizer.default' => 'buildOrganizerDefault',
                'NotificationSystem.buildConfig' => 'buildNotificationSystemConfig',
            ];
    }

    /**
     * @inheritDoc
     */
    public function implementedActions(): array
    {
        /** @var \AccessControl\Model\Behavior\AccessControlBehavior $behavior */
        $behavior = $this->behaviors()->get('AccessControl');

        $actions = [
            'view',
            'create',
            'detail',
            'update',
            'delete',
            'settings',
        ];

        $actions = array_merge($actions, $behavior->implementedActions());

        return $actions;
    }

    /**
     * Generic method that lets the system know its ready for management, which means calculations and appetite
     * are configured.
     *
     * @return bool
     */
    public function isSectionReady(): bool
    {
        $riskCalculationsTable = FactoryLocator::get('Table')->get('RiskCalculations');
        $riskAppetitesTable = FactoryLocator::get('Table')->get('RiskAppetites');

        /** @var \App\Model\Entity\RiskCalculation $calculation */
        $calculation = $riskCalculationsTable->getCalculation('Risks');

        /** @var \App\Model\Entity\RiskAppetite $appetite */
        $appetite = $riskAppetitesTable->getAppetite('Risks');

        return $calculation->isMethodConfigured() && $appetite->isMethodConfigured();
    }

    /**
     * Initialize method
     *
     * @param array $config The configuration for the Table.
     * @return void
     */
    public function initialize(array $config): void
    {
        parent::initialize($config);

        $this->setTable('risks');
        $this->setDisplayField('title');
        $this->setPrimaryKey('id');

        $this->configureSection([
            'singular' => __('Asset Risk'),
            'plural' => __('Asset Risks'),
            'group' => 'risk',
        ]);

        $this->belongsToMany('Assets');
        $this->belongsToMany('ComplianceManagements');
        $this->belongsToMany('Projects');
        $this->belongsToMany('RiskAppetiteThresholds');
        $this->belongsToMany('RiskExceptions');
        $this->belongsToMany('SecurityServices');
        $this->belongsToMany('DataAssets', [
            'joinTable' => 'data_assets_risks',
            'foreignKey' => 'risk_id',
            'targetForeignKey' => 'data_asset_id',
            'conditions' => [
                'DataAssetsRisks.model' => 'Risks',
            ],
        ]);
        $this->belongsToMany('Goals');

        $this->belongsToMany('SecurityIncidents', [
            'joinTable' => 'risks_security_incidents',
            'foreignKey' => 'risk_id',
            'targetForeignKey' => 'security_incident_id',
            'conditions' => [
                'RisksSecurityIncidents.risk_type' => 'asset-risk',
            ],
        ]);
        $this->belongsToMany('ThreatTags', [
            'className' => 'Threats',
            'joinTable' => 'risks_threats',
            'foreignKey' => 'risk_id',
            'targetForeignKey' => 'threat_id',

        ]);
        $this->belongsToMany('VulnerabilityTags', [
            'className' => 'Vulnerabilities',
            'joinTable' => 'risks_vulnerabilities',
            'foreignKey' => 'risk_id',
            'targetForeignKey' => 'vulnerability_id',
        ]);
        $this->belongsToMany('SecurityPolicies', [
            'joinTable' => 'risks_security_policies',
            'foreignKey' => 'risk_id',
            'targetForeignKey' => 'security_policy_id',
            'conditions' => [
                'RisksSecurityPolicies.risk_type' => 'asset-risk',
            ],
        ]);
        $this->belongsToMany('SecurityPoliciesTreatment', [
            'className' => 'SecurityPolicies',
            'joinTable' => 'risks_security_policies',
            'foreignKey' => 'risk_id',
            'targetForeignKey' => 'security_policy_id',
            'conditions' => [
                'RisksSecurityPolicies.risk_type' => 'asset-risk',
                'RisksSecurityPolicies.type' => RisksSecurityPoliciesTable::TYPE_TREATMENT,
            ],
        ]);
        $this->belongsToMany('SecurityPoliciesIncident', [
            'className' => 'SecurityPolicies',
            'joinTable' => 'risks_security_policies',
            'foreignKey' => 'risk_id',
            'targetForeignKey' => 'security_policy_id',
            'conditions' => [
                'RisksSecurityPolicies.risk_type' => 'asset-risk',
                'RisksSecurityPolicies.type' => RisksSecurityPoliciesTable::TYPE_INCIDENT,
            ],
        ]);

        if (Plugin::isLoaded('VendorAssessments')) {
            $this->belongsToMany('VendorAssessments.VendorAssessments');
        }

        $this->addBehavior('Auditable', [
            'ignore' => [
                'risk_score', 'risk_score_formula', 'residual_risk', 'residual_risk_formula', 'expired', 'exceptions_issues',
                'controls_issues', 'control_in_design', 'expired_reviews', 'risk_above_appetite',
            ],
            'associations' => [
                'Owners',
                'Stakeholders',
                'Tags' => [
                    'field' => 'title',
                ],
                'Assets',
                'ThreatTags',
                'VulnerabilityTags',
                'SecurityServices',
                'SecurityPoliciesTreatment',
                'RiskExceptions',
                'Projects',
                'SecurityPoliciesIncident',
            ],
        ]);
        $this->addBehavior('Trash'); // place after Auditable
        $this->addBehavior('SectionInfo.SectionInfo');
        $this->addBehavior('FormOrganization.FormOrganization');
        $this->addBehavior('IntegrityCheck.IntegrityCheck');

        if ($this->isSectionReady()) {
            $this->addBehavior('RiskClassification');
        }

        $this->hasMany('RiskReviews', [
            'foreignKey' => 'foreign_key',
            'conditions' => [
                'RiskReviews.model' => 'Risks',
            ],
            'dependent' => true,
            'cascadeCallbacks' => true,
        ]);

        $this->addBehavior('Risk');

        $this->addOptionalBehavior('CustomFields.CustomFields', [
            'moduleRelationships' => [
                'Legals',
                'BusinessUnits',
                'Processes',
                'ThirdParties',
                'Assets',
                'SecurityServices',
                'BusinessContinuityPlans',
                'SecurityPolicies',
                'PolicyExceptions',
                'ThirdPartyRisks',
                'BusinessContinuities',
                'RiskExceptions',
                'ComplianceExceptions',
                'VendorAssessments.VendorAssessments',
                'Projects',
                'SecurityIncidents',
                'AwarenessPrograms.AwarenessPrograms',
                'AccountReviews.AccountReviews',
            ],
        ]);
        $this->addOptionalBehavior('Api.Api');
        $this->addOptionalBehavior('ActivityLog.ActivityLog', [
            'listenTo' => [
                'title',
                'description',
                'tags',
                'review',
                'assets',
                'threat_tags',
                'threats',
                'vulnerability_tags',
                'vulnerabilities',
                'risk_mitigation_strategy_id',
                'security_services',
                'security_policies_treatment',
                'risk_exceptions',
                'projects',
                'residual_score',
                'security_policies_incident',
            ],
        ]);
    }

    /**
     * Base validation rules.
     *
     * @param \Cake\Validation\Validator $validator Validator instance.
     * @return \Cake\Validation\Validator
     */
    public function validationBase(Validator $validator): Validator
    {
        $validator
            ->integer('id')
            ->allowEmptyString('id', null, 'create');

        $validator
            ->scalar('title')
            ->maxLength('title', 255)
            ->notEmptyString('title');

        $validator
            ->scalar('description')
            ->allowEmptyString('description');

        $validator
            ->date('review')
            ->notEmptyDate('review')
            ->add('review', 'strictDate', [
                'rule' => ['strictDate', 'Y-m-d'],
                'provider' => 'app',
            ])
            /**
             * @see \App\Validation\Validation::futureDate()
             */
            ->add('review', 'futureDate', [
                'rule' => ['futureDate', false],
                'provider' => 'app',
                'on' => 'create',
            ]);

        $validator
            ->integer('residual_score')
            ->notEmptyString('residual_score');

        $validator
            ->notEmptyString('risk_mitigation_strategy_id')
            ->inList('risk_mitigation_strategy_id', array_keys(self::mitigationStrategies()));

        $validator
            ->notEmptyArray('owners');

        $validator
            ->notEmptyArray('stakeholders');

        return $validator;
    }

    /**
     * Integrity check validation rules.
     *
     * @param \Cake\Validation\Validator $validator Validator instance.
     * @return \Cake\Validation\Validator
     */
    public function validationIntegrityCheck(Validator $validator): Validator
    {
        $validator
            ->notEmptyArray('assets');

        return $this->validationBase($validator);
    }

    /**
     * Default validation rules.
     *
     * @param \Cake\Validation\Validator $validator Validator instance.
     * @return \Cake\Validation\Validator
     */
    public function validationDefault(Validator $validator): Validator
    {
        $validator->add('assets', 'belongsToMany', [
            'rule' => 'belongsToMany',
            'provider' => 'app',
            'message' => __('This field cannot be left empty'),
        ]);

        return $this->validationBase($validator);
    }

    /**
     * Handles BulkActions validation.
     *
     * @param \Cake\Validation\Validator $validator
     * @return \Cake\Validation\Validator
     */
    public function validationBulkActions(Validator $validator): Validator
    {
        $this->validationDefault($validator);

        return $validator;
    }

    /**
     * API validation rules.
     *
     * @param \Cake\Validation\Validator $validator Validator instance.
     * @return \Cake\Validation\Validator
     */
    public function validationApi(Validator $validator): Validator
    {
        $this->validationDefault($validator);

        $validator
            ->requirePresence('title')
            ->requirePresence('description')
            ->requirePresence('owners')
            ->array('owners')
            ->requirePresence('stakeholders')
            ->array('stakeholders')
            ->requirePresence('tags')
            ->array('tags')
            ->requirePresence('review', 'create')
            ->requirePresence('assets')
            ->array('assets')
            ->requirePresence('threat_tags')
            ->array('threat_tags')
            ->requirePresence('threats')
            ->requirePresence('vulnerability_tags')
            ->array('vulnerability_tags')
            ->requirePresence('vulnerabilities')
            ->requirePresence('risk_mitigation_strategy_id')
            ->requirePresence('security_services')
            ->array('security_services')
            ->requirePresence('security_policies_treatment')
            ->array('security_policies_treatment')
            ->requirePresence('risk_exceptions')
            ->array('risk_exceptions')
            ->requirePresence('projects')
            ->array('projects')
            ->requirePresence('security_policies_incident')
            ->array('security_policies_incident');

        /** @var \App\Model\Behavior\RiskClassificationBehavior $classificationsBehavior */
        $classificationsBehavior = $this->getBehavior('RiskClassification');

        $associationManager = $classificationsBehavior->getRiskAssociationManager();
        $appetiteMethod = $classificationsBehavior->getAppetiteMethod();

        $analysisClassifications = $associationManager->getClassificationAssociations(RiskClassificationBehavior::TYPE_ANALYSIS);
        foreach ($analysisClassifications as $classification) {
            $property = $classification->getProperty();
            $validator->requirePresence($property);
        }

        $analysisClassifications = $associationManager->getClassificationAssociations(RiskClassificationBehavior::TYPE_TREATMENT);
        foreach ($analysisClassifications as $classification) {
            $property = $classification->getProperty();
            $validator->requirePresence($property);
        }

        if ($appetiteMethod == RiskAppetitesTable::TYPE_INTEGER) {
            $validator
                ->requirePresence('residual_score');
        }

        return $validator;
    }

    /**
     * Default build rules.
     *
     * @param \Cake\ORM\RulesChecker $rules Rules
     * @return \Cake\ORM\RulesChecker
     */
    public function buildRules(RulesChecker $rules): RulesChecker
    {
        return $rules;
    }

    /**
     * Before save event auto-creates reviews for a new Asset.
     *
     * @param \Cake\Event\EventInterface $event
     * @param \Cake\ORM\Entity $entity
     * @param \ArrayObject $options
     */
    public function beforeSave(EventInterface $event, Entity $entity, ArrayObject $options): void
    {
        if ($entity->isNew()) {
            $owners = ReviewsBehavior::parseParentOwnersUsingReviewSettingsConfiguration(
                $entity,
                $this,
                'RiskReviews'
            );

            $date = new Date('now');
            $dateFormatted = $date->format('Y-m-d');

            $completedReview = [
                'planned_date' => $dateFormatted,
                'actual_date' => $dateFormatted,
                'description' => __('This Review was automatically created when the Risk item was created.'),
                'reviewers' => $owners,
                'completed' => 1,
                'completed_by_user' => __('System'),
                'next_review' => [
                    'planned_date' => $entity->get('review'),
                    'reviewers' => $owners,
                    'completed' => 0,
                ],
            ];

            $nextReviewAlias = $this->getAssociation('RiskReviews')->getBehavior('Reviews')->getNextReviewAlias();

            $this->patchEntity($entity, [
                'risk_reviews' => [
                    0 => $completedReview,
                ],
            ], [
                'validate' => false,
                'associated' => [
                    'RiskReviews' => [
                        'validate' => false,
                    ],
                    'RiskReviews.UserField_Reviewers_Users',
                    'RiskReviews.UserField_Reviewers_Groups',
                    'RiskReviews.' . $nextReviewAlias,
                    'RiskReviews.' . $nextReviewAlias . '.UserField_Reviewers_Users',
                    'RiskReviews.' . $nextReviewAlias . '.UserField_Reviewers_Groups',
                ],
            ]);
        }

        //        if ($entity->hasErrors() === false && $entity->isNew() === false && !isset($options['skipRecalculation'])) {
        //            $riskClassificationsRisksTable = FactoryLocator::get('Table')->get('RiskClassificationsRisks');
        //            $numberOfAffected = $riskClassificationsRisksTable->deleteAll([
        //                'risk_id' => $entity->get('id'),
        //            ]);
        //
        //            Log::write('debug', (string) $numberOfAffected);
        //        }
    }

    /**
     * After save workaround.
     *
     * @param \Cake\Event\EventInterface $event Event.
     * @param \Cake\ORM\Entity $entity Entity.
     * @param \ArrayObject $options Options.
     * @return void
     */
    public function afterSaveCommit(EventInterface $event, Entity $entity, ArrayObject $options): void
    {
        if (!isset($options['triggeredByReviews'])) {
            /** @var \App\Model\Behavior\ReviewsBehavior $reviewBehavior */
            $reviewBehavior = $this->getAssociation('RiskReviews')->getBehavior('Reviews');
            //            $reviewBehavior->handleAfterSavePlannedDate('review', $entity, $options);
        }
    }

    public function buildFieldData(EventInterface $event, Collection $collection): void
    {
        $collection
            ->text('_object', [
                'label' => __('Object'),
            ])
            ->number('id', [
                'label' => __('ID'),
                'extensions' => [
                    'Macros.Macro',
                ],
            ])
            ->text('title', [
                'label' => __('Name'),
                'description' => __('For Example: Laptops can be stolen or lost, Etc'),
                'extensions' => [
                    'Macros.Macro',
                    'InlineEdit.InlineEdit',
                    'CustomLabels.CustomLabels' => [
                        'label' => true,
                        'description' => true,
                    ],
                ],
            ])
            ->textarea('description', [
                'label' => __('Description'),
                'extensions' => [
                    'Macros.Macro',
                    'InlineEdit.InlineEdit',
                    'CustomLabels.CustomLabels' => [
                        'label' => true,
                        'description' => true,
                        'hide' => true,
                    ],
                ],
            ])
            ->userField('Owners', [
                'label' => __('Risk GRC Contact'),
                'extensions' => [
                    'Macros.Macro',
                    'InlineEdit.InlineEdit',
                    'CustomLabels.CustomLabels' => [
                        'label' => true,
                        'description' => true,
                    ],
                ],
            ])
            ->userField('Stakeholders', [
                'label' => __('Risk Originator Contact'),
                'description' => __('The department where the Risk originated. For example if Finance has a Risk then Finance group should be selected in this field.'),//phpcs:ignore
                'extensions' => [
                    'Macros.Macro',
                    'InlineEdit.InlineEdit',
                    'CustomLabels.CustomLabels' => [
                        'label' => true,
                        'description' => true,
                    ],
                ],
            ])
            ->taggable('Tags', [
                'label' => __('Tags'),
                'extensions' => [
                    'Macros.Macro',
                    'InlineEdit.InlineEdit',
                    'CustomLabels.CustomLabels' => [
                        'label' => true,
                        'description' => true,
                        'hide' => true,
                    ],
                ],
            ])
            ->date('review', [
                'label' => __('Next Review Date'),
                'description' => __('eramba will automatically create Review records based on the dates you define in this field.'),//phpcs:ignore
                'extensions' => [
                    'Macros.Macro',
                    'CustomLabels.CustomLabels' => [
                        'label' => true,
                        'description' => true,
                    ],
                ],
            ])
            ->multiselect('ThreatTags', [
                'label' => __('Threat Tags'),
                'options' => [$this->getAssociation('ThreatTags'), 'getList'],
                'extensions' => [
                    'Macros.Macro' => [
                        'name' => 'threat',
                    ],
                    'InlineEdit.InlineEdit',
                    'CustomLabels.CustomLabels' => [
                        'alias' => 'Threat',
                        'label' => true,
                        'description' => true,
                        'hide' => true,
                    ],
                ],
            ])
            ->textarea('threats', [
                'label' => __('Threat Description'),
                'extensions' => [
                    'Macros.Macro' => [
                        'name' => 'threat_description',
                    ],
                    'InlineEdit.InlineEdit',
                    'CustomLabels.CustomLabels' => [
                        'label' => true,
                        'description' => true,
                        'hide' => true,
                    ],
                ],
            ])
            ->multiselect('VulnerabilityTags', [
                'label' => __('Vulnerabilities Tags'),
                'options' => [$this->getAssociation('VulnerabilityTags'), 'getList'],
                'extensions' => [
                    'Macros.Macro' => [
                        'name' => 'vulnerability',
                    ],
                    'InlineEdit.InlineEdit',
                    'CustomLabels.CustomLabels' => [
                        'alias' => 'Vulnerability',
                        'label' => true,
                        'description' => true,
                        'hide' => true,
                    ],
                ],
            ])
            ->textarea('vulnerabilities', [
                'label' => __('Vulnerabilities Description'),
                'extensions' => [
                    'Macros.Macro' => [
                        'name' => 'vulnerability_description',
                    ],
                    'InlineEdit.InlineEdit',
                    'CustomLabels.CustomLabels' => [
                        'label' => true,
                        'description' => true,
                        'hide' => true,
                    ],
                ],
            ])
            ->select('risk_mitigation_strategy_id', [
                'label' => __('Risk Treatment'),
                'description' => __('Select the current treatment for this Risk'),
                'options' => [$this, 'mitigationStrategies'],
                'extensions' => [
                    'Macros.Macro' => [
                        'name' => 'treatment',
                    ],
                    'InlineEdit.InlineEdit',
                    'CustomLabels.CustomLabels' => [
                        'label' => true,
                        'description' => true,
                    ],
                ],
            ])
            ->multiselect('SecurityServices', [
                'label' => __('Treatment: Internal Controls'),
                'options' => [$this->getAssociation('SecurityServices'), 'getList'],
                'extensions' => [
                    'Macros.Macro',
                    'InlineEdit.InlineEdit',
                    'CustomLabels.CustomLabels' => [
                        'label' => true,
                        'description' => true,
                        'hide' => true,
                    ],
                ],
            ])
            ->multiselect('SecurityPoliciesTreatment', [
                'label' => __('Treatment: Policies'),
                'options' => [$this->getAssociation('SecurityPoliciesTreatment'), 'getListWithType'],
                'extensions' => [
                    'Macros.Macro' => [
                        'name' => 'treatment_document',
                    ],
                    'InlineEdit.InlineEdit',
                    'CustomLabels.CustomLabels' => [
                        'alias' => 'SecurityPolicyTreatment',
                        'label' => true,
                        'description' => true,
                        'hide' => true,
                    ],
                    'JoinData',
                ],
            ])
            ->multiselect('SecurityPoliciesIncident', [
                'label' => __('Risk Response Documents'),
                'options' => [$this->getAssociation('SecurityPoliciesIncident'), 'getListWithType'],
                'extensions' => [
                    'Macros.Macro' => [
                        'name' => 'risk_response_document',
                    ],
                    'InlineEdit.InlineEdit',
                    'CustomLabels.CustomLabels' => [
                        'alias' => 'SecurityPolicyIncident',
                        'label' => true,
                        'description' => true,
                        'hide' => true,
                    ],
                    'JoinData',
                ],
            ])
            ->multiselect('RiskExceptions', [
                'label' => __('Treatment: Risk Exceptions'),
                'options' => [$this->getAssociation('RiskExceptions'), 'getList'],
                'extensions' => [
                    'Macros.Macro',
                    'InlineEdit.InlineEdit',
                    'CustomLabels.CustomLabels' => [
                        'label' => true,
                        'description' => true,
                    ],
                ],
            ])
            ->multiselect('Projects', [
                'label' => __('Treatment: Projects'),
                'options' => [$this->getAssociation('Projects'), 'getList'],
                'extensions' => [
                    'Macros.Macro',
                    'InlineEdit.InlineEdit',
                    'CustomLabels.CustomLabels' => [
                        'label' => true,
                        'description' => true,
                        'hide' => true,
                    ],
                ],
            ])
            ->select('residual_score', [
                'label' => __('Residual Percentage Coefficient'),
                'options' => $this->getPercentageOptions(),//@phpstan-ignore-line
                'extensions' => [
                    'Macros.Macro',
                    'CustomLabels.CustomLabels' => [
                        'label' => true,
                        'description' => true,
                    ],
                ],
            ])
            ->multiselect('SecurityPolicies', [
                'label' => __('Policies'),
                'options' => [$this->getAssociation('SecurityPolicies'), 'getList'],
            ])
            ->multiselect('SecurityIncidents', [
                'label' => __('Security Incidents'),
                'options' => [$this->getAssociation('SecurityIncidents'), 'getList'],
            ])
            ->multiselect('DataAssets', [
                'label' => __('Data Assets'),
                'options' => [$this->getAssociation('DataAssets'), 'getList'],
                'extensions' => [
                    'Macros.Macro',
                ],
            ])
            ->date('created', [
                'label' => __('Created'),
                'extensions' => [
                    'Macros.Macro',
                ],
            ])
            ->date('modified', [
                'label' => __('Modified'),
                'extensions' => [
                    'Macros.Macro',
                ],
            ])
            ->date('edited', [
                'label' => __('Edited'),
                'extensions' => [
                    'Macros.Macro',
                ],
            ])
            ->date('deleted_date', [
                'label' => __('Deleted Date'),
            ]);

        $collection
            ->multiselect('Assets', [
                'label' => __('Related Assets'),
                'options' => [$this->Assets, 'getList'],
                'extensions' => [
                    'Macros.Macro',
                    'CustomLabels.CustomLabels' => [
                        'label' => true,
                        'description' => true,
                    ],
                ],
            ])
            ->checkbox('auto_threats_updates', [
                'label' => __('Auto Update Threats And Vulnerabilities'),
            ]);

        if (Plugin::isLoaded('VendorAssessments')) {
            $collection
                ->multiselect('VendorAssessments', [
                    'label' => __('Online Assessments'),
                    'extensions' => [
                        'Macros.Macro',
                    ],
                ]);
        }
    }

    /**
     * Default form organization config.
     *
     * @param \Cake\Event\EventInterface $event Event.
     * @param \FormOrganization\FormOrganizer $formOrganizer FormOrganizer.
     * @return void
     */
    public function buildOrganizerDefault(EventInterface $event, FormOrganizer $formOrganizer): void
    {
        /** @var \FieldData\Model\Behavior\FieldDataBehavior $fieldDataBehavior */
        $fieldDataBehavior = $this->getBehavior('FieldData');
        /** @var \FieldData\Lib\Collection $collection */
        $collection = $fieldDataBehavior->getCollection();

        $formOrganizer
            ->setConfig('defaultWidgetClassName', FieldDataWidget::class);

        $formOrganizer
            ->addWidget([
                'className' => GroupWidget::class,
                'name' => 'group__general',
                'order' => true,
                'label' => __('General'),
            ])
            ->addWidget([
                'order' => true,
                'subject' => $collection->get('title'),
            ])
            ->addWidget([
                'order' => true,
                'optional' => true,
                'subject' => $collection->get('description'),
            ])
            ->addWidget([
                'order' => true,
                'subject' => $collection->get('Owners'),
                'insertOptions' => [
                    'listeners' => [
                        'QuickAdd.QuickAdd' => [
                            'targetTable' => $this->getTableLocator()->get('Users'),
                        ],
                    ],
                    'empty' => true,
                ],
            ])
            ->addWidget([
                'order' => true,
                'subject' => $collection->get('Stakeholders'),
                'insertOptions' => [
                    'listeners' => [
                        'QuickAdd.QuickAdd' => [
                            'targetTable' => $this->getTableLocator()->get('Users'),
                        ],
                    ],
                    'empty' => true,
                ],
            ])
            ->addWidget([
                'order' => true,
                'optional' => true,
                'subject' => $collection->get('Tags'),
                'insertOptions' => [
                    'empty' => true,
                ],
                'settings' => [
                    'hidden' => true,
                ],
            ])
            ->addWidget([
                'order' => true,
                'subject' => $collection->get('review'),
                'insert' => function (FormInterface $form) use ($collection) {
                    $entity = $form->getContext()->entity();

                    $reviewListeners = [];
                    if (!$entity->isNew()) {
                        $reviewListeners[] = 'ReadOnly';
                    }

                    /** @var \FieldData\Form\Form $form */
                    $form
                        ->add($collection->get('review'), [
                            'listeners' => $reviewListeners,
                        ]);
                },
            ])
            ->addWidget([
                'className' => GroupWidget::class,
                'name' => 'group__analysis',
                'order' => true,
                'label' => __('Analysis'),
            ])
            ->addWidget([
                'order' => true,
                'subject' => $collection->get('Assets'),
                'insert' => function (FormInterface $form) use ($collection) {
                    /** @var \FieldData\Form\Form $form */
                    $form
                        ->add($collection->get('Assets'), [
                            'listeners' => [
                                'FormReload',
                                'QuickAdd.QuickAdd' => [
                                    'targetTable' => $this->getAssociation('Assets'),
                                ],
                            ],
                            'empty' => true,
                        ]);
                    //                        ->add($collection->get('auto_threats_updates'));
                },
            ])
            ->addWidget([
                'order' => true,
                'optional' => true,
                'subject' => $collection->get('ThreatTags'),
                'insertOptions' => [
                    'listeners' => [
                        'QuickAdd.QuickAdd' => [
                            'targetTable' => $this->getTableLocator()->get('Threats'),
                        ],
                    ],
                    'empty' => true,
                ],
            ])
            ->addWidget([
                'order' => true,
                'optional' => true,
                'subject' => $collection->get('threats'),
            ])
            ->addWidget([
                'order' => true,
                'optional' => true,
                'subject' => $collection->get('VulnerabilityTags'),
                'insertOptions' => [
                    'listeners' => [
                        'QuickAdd.QuickAdd' => [
                            'targetTable' => $this->getTableLocator()->get('Vulnerabilities'),
                        ],
                    ],
                    'empty' => true,
                ],
            ])
            ->addWidget([
                'order' => true,
                'optional' => true,
                'subject' => $collection->get('vulnerabilities'),
            ])
            ->addWidget([
                'className' => FormOrganizerWidget::class,
                'name' => 'analysis_classifications',
                'order' => false,
                'label' => __('Analysis Classifications Widget'),
                'insert' => function (FormInterface $form) use ($collection) {
                    /** @var \FieldData\Form\Form $form */
                    $analysisWidget = new RiskClassificationsWidget('analysis', [
                        'type' => RiskClassificationBehavior::TYPE_ANALYSIS,
                        'model' => $this,
                    ]);

                    $form->add($analysisWidget);
                },
            ])
            ->addWidget([
                'className' => GroupWidget::class,
                'name' => 'group__treatment',
                'order' => true,
                'label' => __('Treatment'),
            ])
            ->addWidget([
                'order' => true,
                'subject' => $collection->get('risk_mitigation_strategy_id'),
                'insertOptions' => [
                    'listeners' => [
                        'FormReload',
                    ],
                    'empty' => true,
                ],
            ])
            ->addWidget([
                'order' => true,
                'subject' => $collection->get('SecurityServices'),
                'insertOptions' => [
                    'listeners' => [
                        'FormReload',
                        'QuickAdd.QuickAdd' => [
                            'targetTable' => $this->getAssociation('SecurityServices'),
                        ],
                    ],
                    'empty' => true,
                ],
            ])
            ->addWidget([
                'order' => true,
                'subject' => $collection->get('SecurityPoliciesTreatment'),
                'insertOptions' => [
                    'listeners' => [
                        'FormReload',
                        'QuickAdd.QuickAdd' => [
                            'targetTable' => $this->getAssociation('SecurityPolicies'),
                        ],
                    ],
                    'empty' => true,
                ],
            ])
            ->addWidget([
                'order' => true,
                'subject' => $collection->get('RiskExceptions'),
                'insertOptions' => [
                    'listeners' => [
                        'FormReload',
                        'QuickAdd.QuickAdd' => [
                            'targetTable' => $this->getAssociation('RiskExceptions'),
                        ],
                    ],
                    'empty' => true,
                ],
            ])
            ->addWidget([
                'order' => true,
                'subject' => $collection->get('Projects'),
                'insertOptions' => [
                    'listeners' => [
                        'FormReload',
                        'QuickAdd.QuickAdd' => [
                            'targetTable' => $this->getAssociation('Projects'),
                        ],
                    ],
                    'empty' => true,
                ],
            ])
            ->addWidget([
                'className' => FormOrganizerWidget::class,
                'name' => 'treatment_classifications',
                'order' => false,
                'label' => __('Treatment Classifications Widget'),
                'insert' => function (FormInterface $form) use ($collection) {
                    /** @var \FieldData\Form\Form $form */
                    $treatment = new RiskClassificationsWidget('treatment', [
                        'type' => RiskClassificationBehavior::TYPE_TREATMENT,
                        'model' => $this,
                    ]);

                    $form->add($treatment);
                },
            ])
            ->addWidget([
                'className' => GroupWidget::class,
                'name' => 'group__response_plan',
                'order' => true,
                'label' => __('Risk Response Plan'),
            ])
            ->addWidget([
                'order' => true,
                'optional' => true,
                'subject' => $collection->get('SecurityPoliciesIncident'),
                'insertOptions' => [
                    'listeners' => [
                        'QuickAdd.QuickAdd' => [
                            'targetTable' => $this->getAssociation('SecurityPolicies'),
                        ],
                    ],
                    'empty' => true,
                ],
                'settings' => [
                    'hidden' => true,
                ],
            ]);
    }

    public function formDefault(FormInterface $form): FormInterface
    {
        /** @var \FormOrganization\Model\Behavior\FormOrganizationBehavior $formOrganizationBehavior */
        $formOrganizationBehavior = $this->getBehavior('FormOrganization');

        $organizer = $formOrganizationBehavior->getOrganizer('default');
        $organizer->organize($form);

        return $form;
    }

    public function formBulkActions(FormInterface $form): FormInterface
    {
        return $this->getBehavior('Risk')->setFormBulkActions($form);
    }

    public function buildAdvancedFilters(EventInterface $event, FilterConfigurationBuilder $config): void
    {
        $config
            ->group('general')
            ->dynamicStatusField('DynamicStatus_RiskReview-expired', 'RiskReview-expired')
            ->dynamicStatusField(
                'DynamicStatus_RiskReview-deadline-approaching',
                'RiskReview-deadline-approaching'
            );

        $config
            ->group('analysis')
            ->multipleSelectField('Asset', [$this->Assets, 'getList'], [
                'fieldData' => 'Assets',
                'count' => true,
                'showDefault' => true,
                'insertOptions' => [
                    'before' => 'Threat',
                ],
            ])
            ->multipleSelectField('Asset-BusinessUnit', [FactoryLocator::get('Table')->get('BusinessUnits'), 'getList'], [
                'fieldData' => 'Assets.BusinessUnits',
                'count' => true,
                'insertOptions' => [
                    'after' => 'Asset',
                ],
            ]);
    }

    public function getAdvancedFilterSeed(SeedCollection $collection): SeedCollection
    {
        $allItems = $collection->add('AllItems');

        if (Plugin::isLoaded('VendorAssessments')) {
            $allItems->addParam('VendorAssessments__show', 1);
            $allItems->addParam('VendorAssessments__count', 1);
        }

        $newComments = $collection->add('Comments.NewComments');
        $newComments->showOnly([$this->getDisplayField(), 'comment_message']);

        $newAttachments = $collection->add('Attachments.NewAttachments');
        $newAttachments->showOnly([$this->getDisplayField(), 'attachment_filename']);

        $newItems = $collection->add('NewItems');
        $newItems->showOnly([$this->getDisplayField()]);

        $updatedItems = $collection->add('UpdatedItems');
        $updatedItems->showOnly([$this->getDisplayField()]);

        $collection->add('ExpiredReviews', [
            'reviewModel' => 'RiskReviews',
            'filterName' => __('Risks with Expired Reviews'),
        ]);

        $collection->add('RiskReviewDeadlineApproaching');

        return $collection;
    }

    public function relatedFilters(FilterConfigurationBuilder $config, $filterName = null): void
    {
        if ($filterName === null) {
            $filterName = Inflector::singularize($this->getAlias());
        }

        $config
            ->group('risks', [
                'name' => $this->getSection()->getSingular(),
            ])
            ->multipleSelectField($filterName, [$this, 'getList'], [
                'fieldData' => $this->getAlias(),
                'count' => true,
                'label' => $this->getSection()->getSingular(),
            ]);
    }

    public function buildDynamicStatusConfig(EventInterface $event, StatusConfigurationBuilder $config): void
    {
        $config
            // fields
            ->group('fields', __('Fields'))
            ->multipleSelect('Asset', [$this->Assets, 'getList'], [
                'fieldData' => 'Assets',
            ]);

        $config
            // functions
            ->group('function', __('Functions'))
            ->relatedCounts('Assets');

        $config
            // related statuses
            ->group('related-statuses', __('Related Statuses'))
            ->relatedStatuses('Assets');
    }

    public function buildReportsConfig(EventInterface $event, ArrayObject $config): void
    {
        $config['table']['model'] = [
            'RiskReviews', 'Assets', 'RiskExceptions', 'ComplianceManagements', 'SecurityIncidents',
        ];

        $config['table']['fields'] = array_merge($config['table']['fields'], [
            'id',
            'title',
            'description',
            'review',
            'threats',
            'vulnerabilities',
            'Asset' => 'Assets',
            'Owner' => 'Owners',
            'Stakeholder' => 'Stakeholders',
            'Threat' => 'ThreatTags',
            'Vulnerability' => 'VulnerabilityTags',
            'risk_mitigation_strategy_id',
            'SecurityService' => 'SecurityServices',
            'SecurityPolicyTreatment' => 'SecurityPoliciesTreatment',
            'RiskException' => 'RiskExceptions',
            'Project' => 'Projects',
            'SecurityPolicyIncident' => 'SecurityPoliciesIncident',
            'DataAsset' => 'DataAssets',
            'Tag' => 'Tags',
            'edited',
        ]);

        if (Plugin::isLoaded('VendorAssessments')) {
            $config['table']['fields']['VendorAssessments'] = 'VendorAssessments';
        }

        $config['chart'][1] = [
            'title' => __('Risks by Business Unit'),
            'description' => __('We show the relationship in between Risks and Business Units (trough the assets they have in common).'),
            'type' => ReportBlockChartSettingsTable::TYPE_PIE,
            'templateType' => ReportTemplatesTable::TYPE_SECTION,
            'visualisations' => true,
            'className' => 'CollectionByPropertyChart',
            'params' => [
                'property' => 'Assets.BusinessUnits',
            ],
            'finder' => [
                'contain' => [
                    'Assets' => [
                        'fields' => ['id'],
                        'BusinessUnits' => [
                            'fields' => ['id', 'name'],
                        ],
                    ],
                ],
            ],
        ];
        $config['chart'][2] = [
            'title' => __('Risks and related Objects'),
            'description' => __('This tree shows the risks and its associated assets, third parties, vulnerabilities, threats, controls, policies, exceptions and compliance package items.'),// phpcs:ignore
            'type' => ReportBlockChartSettingsTable::TYPE_TREE,
            'templateType' => ReportTemplatesTable::TYPE_ITEM,
            'className' => 'RelatedObjectsChart',
            'params' => [
                'assoc' => [
                    'Assets',
                    'SecurityServices',
                    'SecurityPolicies',
                    'VulnerabilityTags',
                    'ThreatTags',
                    'RiskExceptions',
                    'ComplianceManagements.CompliancePackageItems',
                ],
            ],
            'finder' => [
                'contain' => [
                    'Assets' => [
                        'fields' => ['id', 'name'],
                    ],
                    'SecurityServices' => [
                        'fields' => ['id', 'name'],
                    ],
                    'SecurityPolicies' => [
                        'fields' => ['id', 'index'],
                    ],
                    'VulnerabilityTags' => [
                        'fields' => ['id', 'name'],
                    ],
                    'ThreatTags' => [
                        'fields' => ['id', 'name'],
                    ],
                    'RiskExceptions' => [
                        'fields' => ['id', 'title'],
                    ],
                    'ComplianceManagements' => [
                        'fields' => ['id', 'compliance_package_item_id'],
                        'CompliancePackageItems' => [
                            'fields' => ['id', 'compliance_package_id', 'item_id', 'name'],
                            'CompliancePackages' => [
                                'fields' => ['id', 'compliance_package_regulator_id'],
                                'CompliancePackageRegulators' => [
                                    'fields' => ['id', 'name'],
                                ],
                            ],
                        ],
                    ],
                ],
            ],
        ];
    }

    /**
     * Notification system config.
     *
     * @param \Cake\Event\EventInterface $event Event.
     * @param \ArrayObject $notifications Notifications config.
     * @param \ArrayObject $options Options config.
     * @return void
     */
    public function buildNotificationSystemConfig(EventInterface $event, ArrayObject $notifications, ArrayObject $options): void// phpcs:ignore
    {
        /** @var \App\Model\Table\FiltersTable $filtersTable */
        $filtersTable = $this->fetchTable('Filters');
        $expiredReviewsFilter = $filtersTable->find()
            ->where([
                'slug' => 'missing-reviews',
                'model' => 'Risks',
            ])
            ->first();

        if ($expiredReviewsFilter) {
            $options['seed']['filer-risks-expired-reviews'] = [
                'name' => __('Risks with Expired Reviews'),
                'slug' => 'filer-risks-expired-reviews',
                'notification' => 'advanced_filters',
                'notification_users' => [
                    'Group-10',
                ],
                'filter_id' => $expiredReviewsFilter->get('id'),
                'report_attachment_type' => NotificationSystemItemsTable::REPORT_ATTACHEMENT_PDF,
                'report_send_empty_results' => 1,
                'trigger_period' => 6,
                'email_subject' => __('Expired Asset Risks'),
                'email_body' => nl2br(__('Hello,

This is a weekly report with all expired Risks.

Click on the link below to access the module:

%SECTION_URL%

Thank you')),
            ];
        }

        $deadlineApproachingFilter = $filtersTable->find()
            ->where([
                'slug' => 'risks-deadline-approaching',
                'model' => 'Risks',
            ])
            ->first();

        if ($deadlineApproachingFilter) {
            $options['seed']['filer-risks-deadline-approaching'] = [
                'name' => __('Risks with Reviews expiring in the next couple of weeks'),
                'slug' => 'filer-risks-deadline-approaching',
                'notification' => 'advanced_filters',
                'notification_users' => [
                    'Group-10',
                ],
                'filter_id' => $deadlineApproachingFilter->get('id'),
                'report_attachment_type' => NotificationSystemItemsTable::REPORT_ATTACHEMENT_PDF,
                'report_send_empty_results' => 1,
                'trigger_period' => 6,
                'email_subject' => __('Asset Risks Expiring in the next couple of weeks'),
                'email_body' => nl2br(__('Hello,

This is a weekly report with all Asset Risk Reviews expiring in the next couple of weeks.

Click on the link below to access the module:

%SECTION_URL%

Thank you')),
            ];
        }

        $this->seedNotification('created', [
            'notification_system_item_custom_roles' => [
                'Risks.Owners',
                'Risks.Stakeholders',
            ],
        ]);
        $this->seedNotification('edited', [
            'notification_system_item_custom_roles' => [
                'Risks.Owners',
                'Risks.Stakeholders',
            ],
        ]);
        $this->seedNotification('deleted', [
            'notification_system_item_custom_roles' => [
                'Risks.Owners',
                'Risks.Stakeholders',
            ],
        ]);
        $this->seedNotification('widget_object', [
            'notification_system_item_custom_roles' => [
                'Risks.Owners',
                'Risks.Stakeholders',
            ],
        ]);
    }

    public function buildImportToolConfig(EventInterface $event, ArrayObject $config): void
    {
        $collection = $this->getBehavior('FieldData')->getCollection();
        /** @var \App\Model\Behavior\RiskClassificationBehavior $classificationsBehavior */
        $classificationsBehavior = $this->getBehavior('RiskClassification');

        $associationManager = $classificationsBehavior->getRiskAssociationManager();
        $appetiteMethod = $classificationsBehavior->getAppetiteMethod();

        $config['title'] = [
            'name' => $collection->get('title')->getLabel(),
            'headerTooltip' => __('This field is mandatory, give this risk a descriptive title.'),
        ];
        $config['description'] = [
            'name' => $collection->get('description')->getLabel(),
            'headerTooltip' => __('Optional, describe this risk scenario, context, triggers, Etc.'),
        ];
        $config['Owners'] = UserFields::getImportArgsFieldData('Owners', [
            'name' => $collection->get('Owners')->getLabel(),
        ], false);
        $config['Stakeholders'] = UserFields::getImportArgsFieldData('Stakeholders', [
            'name' => $collection->get('Stakeholders')->getLabel(),
        ], false);
        $config['tags'] = [
            'name' => $collection->get('Tags')->getLabel(),
            'headerTooltip' => __('Optional and accepts tags separated by "|". For example "Critical|High Risk|Financial Risk"'),
            'multiple' => true,
        ];
        $config['review'] = [
            'name' => $collection->get('review')->getLabel(),
            'headerTooltip' => __('This field is mandatory, define a date when this risk will be reviewed, the format for the date is YYYY-MM-DD and the date must be in the future.'),
        ];
        $config['Assets'] = [
            'name' => $collection->get('Assets')->getLabel(),
            'headerTooltip' => __('This field is mandatory, accepts multiple names separated by "|". You need to enter the name of an asset, you can find them at Asset Management / Asset Identification.'),
            'association' => 'Assets',
            'objectAutoFind' => true,
        ];
        $config['ThreatTags'] = [
            'name' => $collection->get('ThreatTags')->getLabel(),
            'headerTooltip' => __('Optional, accepts multiple names separated by "|". You need to enter the name of a threat, you can find them at Risk Management / Asset Risk Management / Settings / Threats.'),
            'association' => 'ThreatTags',
            'objectAutoFind' => true,
        ];
        $config['threats'] = [
            'name' => $collection->get('threats')->getLabel(),
            'headerTooltip' => __('Optional, describe the context of the threats vectors for this risk.'),
        ];
        $config['VulnerabilityTags'] = [
            'name' => $collection->get('VulnerabilityTags')->getLabel(),
            'headerTooltip' => __('Optional, accepts multiple names separated by "|". You need to enter the name of a vulnerability, you can find them at Risk Management / Asset Risk Management / Settings / Vulnerabilities.'),
            'association' => 'VulnerabilityTags',
            'objectAutoFind' => true,
        ];
        $config['vulnerabilities'] = [
            'name' => $collection->get('vulnerabilities')->getLabel(),
            'headerTooltip' => __('Optional, describe the context of the vulnerabilities vectors for this risk.'),
        ];

        $analysisClassifications = $associationManager->getClassificationAssociations(RiskClassificationBehavior::TYPE_ANALYSIS);
        foreach ($analysisClassifications as $classification) {
            $alias = $classification->getAlias();
            $property = $classification->getProperty();
            $fieldData = $collection->get($alias);

            $optionsParser = new OptionsParser($fieldData->getOptions());

            $config[$property] = [
                'name' => $fieldData->getLabel(),
                'headerTooltip' => __('This field is mandatory, enter one from the following options: {0}', [
                    ImportTool::formatList($optionsParser->parse()),
                ]),
            ];
        }

        $config['risk_mitigation_strategy_id'] = [
            'name' => $collection->get('risk_mitigation_strategy_id')->getLabel(),
            'headerTooltip' => __('This field is mandatory, select id of treatment strategy for this risk, can be one of the following values: {0}', [
                ImportTool::formatList(self::mitigationStrategies()),
            ]),
        ];
        $config['SecurityServices'] = [
            'name' => $collection->get('SecurityServices')->getLabel(),
            'headerTooltip' => __('Mandatory / optional depends on "Risk Treatment" input and settings of treatment options, you can find them in risk section settings under Treatment Options. Accepts multiple names separated by "|". You need to enter the name of a control, you can find them at Control Catalog / Internal Controls.'),//phpcs:ignore
            'association' => 'SecurityServices',
            'objectAutoFind' => true,
        ];
        $config['SecurityPoliciesTreatment'] = [
            'name' => $collection->get('SecurityPoliciesTreatment')->getLabel(),
            'headerTooltip' => __('Mandatory / optional depends on "Risk Treatment" input and settings of treatment options, you can find them in risk section settings under Treatment Options. Accepts multiple names separated by "|". You need to enter the name of a policy, you can find them at Control Catalog / Policies.'),//phpcs:ignore
            'association' => 'SecurityPoliciesTreatment',
            'objectAutoFind' => true,
        ];
        $config['RiskExceptions'] = [
            'name' => $collection->get('RiskExceptions')->getLabel(),
            'headerTooltip' => __('Mandatory / optional depends on "Risk Treatment" input and settings of treatment options, you can find them in risk section settings under Treatment Options. Accepts multiple names separated by "|". You need to enter the name of an exception, you can find them at Risk Management / Risk Exceptions.'),
            'association' => 'RiskExceptions',
            'objectAutoFind' => true,
        ];
        $config['Projects'] = [
            'name' => $collection->get('Projects')->getLabel(),
            'headerTooltip' => __('Mandatory / optional depends on "Risk Treatment" input and settings of treatment options, you can find them in risk section settings under Treatment Options. Accepts multiple names separated by "|". You need to enter the name of a project, you can find them at Security Operations / Project Management.'),
            'association' => 'Projects',
            'objectAutoFind' => true,
        ];

        $treatmentClassifications = $associationManager->getClassificationAssociations(RiskClassificationBehavior::TYPE_TREATMENT);
        foreach ($treatmentClassifications as $classification) {
            $alias = $classification->getAlias();
            $property = $classification->getProperty();
            $fieldData = $collection->get($alias);

            $optionsParser = new OptionsParser($fieldData->getOptions());

            $config[$property] = [
                'name' => $fieldData->getLabel(),
                'headerTooltip' => __('This field is mandatory, enter one from the following options: {0}', [
                    ImportTool::formatList($optionsParser->parse()),
                ]),
            ];
        }

        if ($appetiteMethod == RiskAppetitesTable::TYPE_INTEGER) {
            $fieldData = $collection->get('residual_score');
            $optionsParser = new OptionsParser($fieldData->getOptions());

            $config['residual_score'] = [
                'name' => $fieldData->getLabel(),
                'headerTooltip' => __(
                    'This field is mandatory, enter the percentage of Risk Reduction that was achieved by applying Security Controls. Can be one of the following values: {0}',
                    ImportTool::formatList($optionsParser->parse())
                ),
            ];
        }
    }

    public function getMacrosConfig()
    {
        return [
            'assoc' => [
                'Assets',
            ],
        ];
    }

    public function buildSectionInfoConfig(EventInterface $event, ArrayObject $config): void
    {
        $config['map'] = [
            'Assets' => [
                'mandatory' => true,
                'children' => [
                    'BusinessUnits' => [
                        'mandatory' => true,
                    ],
                ],
            ],
            'SecurityServices' => [
                'mandatory' => false,
                'children' => [
                    'SecurityServiceAudits' => [
                        'mandatory' => false,
                    ],
                    'SecurityServiceIssues' => [
                        'mandatory' => false,
                    ],
                    'SecurityServiceMaintenances' => [
                        'mandatory' => false,
                    ],
                ],
            ],
            'Projects' => [
                'mandatory' => false,
                'children' => [
                    'ProjectAchievements' => [
                        'mandatory' => false,
                    ],
                ],
            ],
            'SecurityPolicies' => [
                'mandatory' => false,
            ],
            'RiskExceptions' => [
                'mandatory' => false,
            ],
            'VendorAssessments',
        ];
    }

    /**
     * Custom form finder.
     *
     * @param \Cake\ORM\Query $query Query
     * @return \Cake\ORM\Query
     */
    public function findForm(Query $query)
    {
        return $query
            ->find('classifications')
            ->find('scores')
            ->find('thresholds')
            ->contain([
                'Tags',
                'Assets',
                'ComplianceManagements',
                'DataAssets',
                'Projects',
                'RiskExceptions',
                'SecurityIncidents',
                'SecurityServices',
                'ThreatTags',
                'VulnerabilityTags',
                'SecurityPoliciesTreatment',
                'SecurityPoliciesIncident',
            ]);
    }

    /**
     * Fallback finder used by access control resource sync.
     *
     * @param \Cake\ORM\Query $query Query.
     * @return \Cake\ORM\Query
     */
    public function findClassifications(Query $query): Query
    {
        return $query;
    }

    /**
     * Fallback finder used by access control resource sync.
     *
     * @param \Cake\ORM\Query $query Query.
     * @return \Cake\ORM\Query
     */
    public function findScores(Query $query): Query
    {
        return $query;
    }

    /**
     * Fallback finder used by access control resource sync.
     *
     * @param \Cake\ORM\Query $query Query.
     * @return \Cake\ORM\Query
     */
    public function findThresholds(Query $query): Query
    {
        return $query;
    }

    public function findAdvancedFilter(EventInterface $event, Query $query)
    {
        return $query
            ->contain([
                'RiskReviews',
                'Assets' => [
                    'BusinessUnits',
                ],
            ]);
    }

    /**
     * Api configuration.
     *
     * @param \Cake\Event\EventInterface $event Event.
     * @param \ArrayObject $config Config.
     * @return void
     */
    public function buildNewApiConfig(EventInterface $event, ArrayObject $config): void
    {
        /** @var \Api\Model\Behavior\ApiBehavior $apiBehavior */
        $apiBehavior = $this->getBehavior('Api');

        $config['routes'][__('Risks')] = [
            $apiBehavior->getIndexRoute(),
            $apiBehavior->getViewRoute(),
            $apiBehavior->getAddRoute(),
            $apiBehavior->getEditRoute(),
            $apiBehavior->getDeleteRoute(),
        ];

        $schema = [
            'id' => [
                'type' => 'integer',
                'readOnly' => true,
            ],
            'title' => [
                'type' => 'string',
            ],
            'description' => [
                'type' => 'string',
            ],
            'threats' => [
                'type' => 'string',
            ],
            'vulnerabilities' => [
                'type' => 'string',
            ],
            'review' => [
                'type' => 'date',
            ],
            'risk_mitigation_strategy_id' => [
                'type' => 'integer',
                'description' => ApiBehavior::optionsDescription(self::mitigationStrategies()),
            ],
            'tags' => [
                'type' => 'array',
                'description' => __('Save as an array of tags ["tag1", "tag2", ...].'),

            ],
            'assets' => [
                'type' => 'array',
            ],
            'projects' => [
                'type' => 'array',
            ],
            'risk_exceptions' => [
                'type' => 'array',
            ],
            'security_services' => [
                'type' => 'array',
            ],
            'threat_tags' => [
                'type' => 'array',
            ],
            'vulnerability_tags' => [
                'type' => 'array',
            ],
            'security_policies_treatment' => [
                'type' => 'array',
            ],
            'security_policies_incident' => [
                'type' => 'array',
            ],

        ];

        if ($this->isSectionReady()) {
            $associationManager = $this->getRiskAssociationManager();
            $collection = $this->getBehavior('FieldData')->getCollection();

            // risk classifications
            $classifications = $associationManager->getClassificationAssociations(RiskClassificationBehavior::TYPE_ANALYSIS);
            foreach ($classifications as $classification) {
                $fieldData = $collection->get($classification->getAlias());

                $optionsParser = new OptionsParser($fieldData->getOptions());
                $options = $optionsParser->parse();

                $schema[$classification->getProperty()] = [
                    'type' => 'integer',
                    'description' => ApiBehavior::optionsDescription($options),
                ];
                //                $apiBehavior->addAssociationProperty($properties, $classification->getAlias(), [
                //                    'description' => ApiBehavior::optionsDescription($options),
                //                ]);
            }
            $classifications = $associationManager->getClassificationAssociations(RiskClassificationBehavior::TYPE_TREATMENT);
            foreach ($classifications as $classification) {
                $fieldData = $collection->get($classification->getAlias());

                $optionsParser = new OptionsParser($fieldData->getOptions());
                $options = $optionsParser->parse();

                $schema[$classification->getProperty()] = [
                    'type' => 'integer',
                    'description' => ApiBehavior::optionsDescription($options),
                ];

                //                $apiBehavior->addAssociationProperty($properties, $classification->getAlias(), [
                //                    'description' => ApiBehavior::optionsDescription($options),
                //                ]);
            }

            // risk scores
            $riskScores = $associationManager->getScoreAssociations(RiskClassificationBehavior::TYPE_ANALYSIS);
            foreach ($riskScores as $riskScore) {
                //                dd($riskScore->getAlias());
                //                $apiBehavior->addAssociationProperty($properties, $riskScore->getAlias(), [
                //                    'readOnly' => true,
                //                ]);
            }
            $riskScores = $associationManager->getScoreAssociations(RiskClassificationBehavior::TYPE_TREATMENT);
            foreach ($riskScores as $riskScore) {
                //                $apiBehavior->addAssociationProperty($properties, $riskScore->getAlias(), [
                //                    'readOnly' => true,
                //                ]);
            }

            // risk thresholds
            $thresholds = $associationManager->getThresholdAssociations(RiskClassificationBehavior::TYPE_ANALYSIS);
            foreach ($thresholds as $threshold) {
                //                $apiBehavior->addAssociationProperty($properties, $threshold->getAlias(), [
                //                    'readOnly' => true,
                //                ]);
            }
            $thresholds = $associationManager->getThresholdAssociations(RiskClassificationBehavior::TYPE_TREATMENT);
            foreach ($thresholds as $threshold) {
                //                $apiBehavior->addAssociationProperty($properties, $threshold->getAlias(), [
                //                    'readOnly' => true,
                //                ]);
            }
        }

        $config['schema'] = array_merge($config['schema'], $schema);
    }

    /**
     * Api configuration.
     *
     * @param \Cake\Event\EventInterface $event Event
     * @param \SwaggerBake\Lib\OpenApi\Schema $schema Schema object
     * @param \SwaggerBake\Lib\Model\ModelDecorator $decorator Model decorator
     * @return void
     */
    public function buildApiConfig(EventInterface $event, Schema $schema, ModelDecorator $decorator): void
    {
        /** @var \Api\Model\Behavior\ApiBehavior $apiBehavior */
        $apiBehavior = $this->getBehavior('Api');

        $properties = $schema->getProperties();

        $residualScoreConfig = [
            'readOnly' => true,
            'minLength' => 0,
        ];
        if ($this->isSectionReady()) {
            /** @var \App\Model\Behavior\RiskClassificationBehavior $classificationsBehavior */
            $classificationsBehavior = $this->getBehavior('RiskClassification');
            $appetiteMethod = $classificationsBehavior->getAppetiteMethod();

            if ($appetiteMethod == RiskAppetitesTable::TYPE_INTEGER) {
                $residualScoreConfig = [
                    'minLength' => 0,
                ];
            }
        }

        $properties = $apiBehavior->filterProperties($properties, [
            'id' => [
                'readOnly' => true,
                'minLength' => 0,
            ],
            'title' => [
                'minLength' => 0,
            ],
            'description' => true,
            'threats' => [
                'minLength' => 0,
            ],
            'vulnerabilities' => [
                'minLength' => 0,
            ],
            'residual_score' => $residualScoreConfig,
            'review' => [
                'description' => ApiBehavior::dateDescription(),
                'minLength' => 0,
            ],
            'risk_mitigation_strategy_id' => [
                'description' => ApiBehavior::optionsDescription(self::mitigationStrategies()),
                'minLength' => 0,
                'enum' => [],
            ],
            'created' => [
                'readOnly' => true,
                'minLength' => 0,
            ],
            'edited' => [
                'readOnly' => true,
                'minLength' => 0,
            ],
        ]);

        $apiBehavior->addUserFieldProperty($properties, 'Owners');
        $apiBehavior->addUserFieldProperty($properties, 'Stakeholders');

        $apiBehavior->addAssociationProperty($properties, 'Tags', [
            'description' => __('Save as an array of tags ["tag1", "tag2", ...].'),
        ]);

        if ($this->isSectionReady()) {
            $associationManager = $this->getRiskAssociationManager();
            $collection = $this->getBehavior('FieldData')->getCollection();

            // risk classifications
            $classifications = $associationManager->getClassificationAssociations(RiskClassificationBehavior::TYPE_ANALYSIS);
            foreach ($classifications as $classification) {
                $fieldData = $collection->get($classification->getAlias());

                $optionsParser = new OptionsParser($fieldData->getOptions());
                $options = $optionsParser->parse();

                $apiBehavior->addAssociationProperty($properties, $classification->getAlias(), [
                    'description' => ApiBehavior::optionsDescription($options),
                ]);
            }
            $classifications = $associationManager->getClassificationAssociations(RiskClassificationBehavior::TYPE_TREATMENT);
            foreach ($classifications as $classification) {
                $fieldData = $collection->get($classification->getAlias());

                $optionsParser = new OptionsParser($fieldData->getOptions());
                $options = $optionsParser->parse();

                $apiBehavior->addAssociationProperty($properties, $classification->getAlias(), [
                    'description' => ApiBehavior::optionsDescription($options),
                ]);
            }

            // risk scores
            $riskScores = $associationManager->getScoreAssociations(RiskClassificationBehavior::TYPE_ANALYSIS);
            foreach ($riskScores as $riskScore) {
                $apiBehavior->addAssociationProperty($properties, $riskScore->getAlias(), [
                    'readOnly' => true,
                ]);
            }
            $riskScores = $associationManager->getScoreAssociations(RiskClassificationBehavior::TYPE_TREATMENT);
            foreach ($riskScores as $riskScore) {
                $apiBehavior->addAssociationProperty($properties, $riskScore->getAlias(), [
                    'readOnly' => true,
                ]);
            }

            // risk thresholds
            $thresholds = $associationManager->getThresholdAssociations(RiskClassificationBehavior::TYPE_ANALYSIS);
            foreach ($thresholds as $threshold) {
                $apiBehavior->addAssociationProperty($properties, $threshold->getAlias(), [
                    'readOnly' => true,
                ]);
            }
            $thresholds = $associationManager->getThresholdAssociations(RiskClassificationBehavior::TYPE_TREATMENT);
            foreach ($thresholds as $threshold) {
                $apiBehavior->addAssociationProperty($properties, $threshold->getAlias(), [
                    'readOnly' => true,
                ]);
            }
        }

        $apiBehavior->addAssociationProperty($properties, 'RiskReviews', [
            'readOnly' => true,
        ]);

        $apiBehavior->addAssociationProperty($properties, 'Assets');
        $apiBehavior->addAssociationProperty($properties, 'ComplianceManagements', [
            'readOnly' => true,
        ]);
        $apiBehavior->addAssociationProperty($properties, 'Projects');
        $apiBehavior->addAssociationProperty($properties, 'RiskAppetiteThresholds', [
            'readOnly' => true,
        ]);
        $apiBehavior->addAssociationProperty($properties, 'RiskExceptions');
        $apiBehavior->addAssociationProperty($properties, 'SecurityServices');
        $apiBehavior->addAssociationProperty($properties, 'DataAssets', [
            'readOnly' => true,
        ]);
        $apiBehavior->addAssociationProperty($properties, 'SecurityIncidents', [
            'readOnly' => true,
        ]);
        $apiBehavior->addAssociationProperty($properties, 'ThreatTags');
        $apiBehavior->addAssociationProperty($properties, 'VulnerabilityTags');
        $apiBehavior->addAssociationProperty($properties, 'SecurityPolicies', [
            'readOnly' => true,
        ]);
        $apiBehavior->addAssociationProperty($properties, 'SecurityPoliciesTreatment');
        $apiBehavior->addAssociationProperty($properties, 'SecurityPoliciesIncident');

        $schema->setProperties($properties);
    }

    /**
     * Base API finder.
     *
     * @param \Cake\ORM\Query $query Query
     * @return \Cake\ORM\Query
     */
    public function findApiBase(Query $query)
    {
        return $query
            ->select([
                'Risks.id', 'Risks.title', 'Risks.description', 'Risks.threats', 'Risks.vulnerabilities',
                'Risks.risk_mitigation_strategy_id', 'Risks.residual_score', 'Risks.review', 'Risks.created', 'Risks.edited',
            ]);
    }

    /**
     * API finder.
     *
     * @param \Cake\ORM\Query $query Query
     * @return \Cake\ORM\Query
     */
    public function findApi(Query $query)
    {
        $query
            ->find('apiBase')
            ->contain([
                'Owners' => [
                    'finder' => 'apiBase',
                ],
                'Stakeholders' => [
                    'finder' => 'apiBase',
                ],
                'Tags' => [
                    'finder' => 'apiBase',
                ],
                'RiskReviews' => [
                    'finder' => 'apiBase',
                ],
                'Assets' => [
                    'finder' => 'apiBase',
                ],
                'ComplianceManagements' => [
                    'finder' => 'apiBase',
                ],
                'Projects' => [
                    'finder' => 'apiBase',
                ],
                'RiskExceptions' => [
                    'finder' => 'apiBase',
                ],
                'SecurityServices' => [
                    'finder' => 'apiBase',
                ],
                'DataAssets' => [
                    'finder' => 'apiBase',
                ],
                'SecurityIncidents' => [
                    'finder' => 'apiBase',
                ],
                'ThreatTags' => [
                    'finder' => 'apiBase',
                ],
                'VulnerabilityTags' => [
                    'finder' => 'apiBase',
                ],
                'SecurityPolicies' => [
                    'finder' => 'apiBase',
                ],
                'SecurityPoliciesTreatment' => [
                    'finder' => 'apiBase',
                ],
                'SecurityPoliciesIncident' => [
                    'finder' => 'apiBase',
                ],
            ]);

        if ($this->isSectionReady()) {
            $associationManager = $this->getRiskAssociationManager();

            // risk classifications
            $classifications = $associationManager->getClassificationAssociations(RiskClassificationBehavior::TYPE_ANALYSIS);
            foreach ($classifications as $classification) {
                $query->contain([$classification->getAlias() => [
                    'finder' => 'apiBase',
                ]]);
            }
            $classifications = $associationManager->getClassificationAssociations(RiskClassificationBehavior::TYPE_TREATMENT);
            foreach ($classifications as $classification) {
                $query->contain([$classification->getAlias() => [
                    'finder' => 'apiBase',
                ]]);
            }

            // risk scores
            $riskScores = $associationManager->getScoreAssociations(RiskClassificationBehavior::TYPE_ANALYSIS);
            foreach ($riskScores as $riskScore) {
                $query->contain([$riskScore->getAlias() => [
                    'finder' => 'apiBase',
                ]]);
            }
            $riskScores = $associationManager->getScoreAssociations(RiskClassificationBehavior::TYPE_TREATMENT);
            foreach ($riskScores as $riskScore) {
                $query->contain([$riskScore->getAlias() => [
                    'finder' => 'apiBase',
                ]]);
            }

            // risk thresholds
            $thresholds = $associationManager->getThresholdAssociations(RiskClassificationBehavior::TYPE_ANALYSIS);
            foreach ($thresholds as $threshold) {
                $query->contain([$threshold->getAlias() => [
                    'finder' => 'apiBase',
                ]]);
            }
            $thresholds = $associationManager->getThresholdAssociations(RiskClassificationBehavior::TYPE_TREATMENT);
            foreach ($thresholds as $threshold) {
                $query->contain([$threshold->getAlias() => [
                    'finder' => 'apiBase',
                ]]);
            }
        }

        return $query;
    }

    /**
     * Integrity check finder.
     *
     * @param \Cake\ORM\Query $query Query.
     * @return \Cake\ORM\Query
     */
    public function findIntegrityCheck(Query $query): Query
    {
        return $query
            ->find('classifications')
            ->contain([
                'Owners',
                'Stakeholders',
                'Assets',
            ]);
    }
}
