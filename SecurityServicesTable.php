<?php

declare(strict_types=1);

namespace App\Model\Table;

use AccessControl\SectionResourceInterface;
use AdvancedFilters\Lib\Configuration\FilterConfigurationBuilder;
use AdvancedFilters\Lib\SeedCollection;
use Api\Model\Behavior\ApiBehavior;
use App\Model\Traits\ListTrait;
use App\Model\Traits\OptionalBehaviorTrait;
use App\Model\Traits\SectionTrait;
use App\Model\Traits\TraverseTrait;
use App\View\Helper\SecurityServicesHelper;
use ArrayObject;
use BulkActions\Control\Listener\BulkActionsListener;
use Cake\Datasource\EntityInterface;
use Cake\Datasource\FactoryLocator;
use Cake\Event\EventInterface;
use Cake\ORM\Locator\LocatorAwareTrait;
use Cake\ORM\Query;
use Cake\ORM\Table;
use Cake\Utility\Hash;
use Cake\Validation\Validation;
use Cake\Validation\Validator;
use Cake\View\View;
use Dashboard\Lib\DashboardManager;
use DynamicStatus\Lib\Configuration\StatusConfigurationBuilder;
use DynamicStatus\Lib\Macros\DynamicStatusIntegerMacro;
use DynamicStatus\Model\Table\DynamicStatusesTable;
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
use Macros\Lib\Macro;
use Macros\Lib\MacroCollection;
use NotificationSystem\Model\Table\NotificationSystemItemsTable;
use Reports\Model\Table\ReportBlockChartSettingsTable;
use Reports\Model\Table\ReportTemplatesTable;
use stdClass;
use SwaggerBake\Lib\Model\ModelDecorator;
use SwaggerBake\Lib\OpenApi\Schema;
use UserFields\Lib\UserFields;
use UserFields\Model\Behavior\UserFieldsBehavior;
use YearlyCalendar\Model\Behavior\YearlyCalendarBehavior;

class SecurityServicesTable extends Table implements SectionResourceInterface, IntegrityCheckCollectionInterface
{
    use SectionTrait;
    use OptionalBehaviorTrait;
    use TraverseTrait;
    use ListTrait;
    use FormAwareTrait;
    use LocatorAwareTrait;
    use IntegrityCheckCollectionTrait;

    public const TYPE_DESIGN = 2;
    public const TYPE_PRODUCTION = 4;
    public const TYPE_RETIRED = 5; // old type, not used

    public static function types(): array
    {
        return [
            self::TYPE_DESIGN => __('Design'),
            self::TYPE_PRODUCTION => __('Production'),
        ];
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
                'DynamicStatus.buildConfig' => 'buildDynamicStatusConfig',
                'AdvancedFilters.buildConfig' => 'buildAdvancedFilters',
                'AdvancedFilters.beforeFind' => 'findAdvancedFilter',
                'NotificationSystem.buildConfig' => 'buildNotificationSystemConfig',
                'Reports.buildConfig' => 'buildReportsConfig',
                'ImportTool.buildConfig' => 'buildImportToolConfig',
                'SectionInfo.buildConfig' => 'buildSectionInfoConfig',
                'Api.buildConfig' => 'buildApiConfig',
                'Api.buildNewConfig' => 'buildNewApiConfig',
                'FormOrganization.buildOrganizer.default' => 'buildOrganizerDefault',
                'FormOrganization.buildOrganizer.bulk' => 'buildOrganizerBulk',
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
        ];

        $actions = array_merge($actions, $behavior->implementedActions());

        return $actions;
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

        $this->setTable('security_services');
        $this->setDisplayField('name');
        $this->setPrimaryKey('id');

        $this->configureSection([
            'singular' => __('Internal Control'),
            'plural' => __('Internal Controls'),
            'group' => 'control',
        ]);

        $this->hasMany('SecurityServiceAudits', [
            'dependent' => true,
            'cascadeCallbacks' => true,
        ]);
        $this->hasMany('SecurityServiceAuditDates', [
            'saveStrategy' => 'replace',
        ]);
        $this->hasMany('SecurityServiceMaintenances', [
            'dependent' => true,
            'cascadeCallbacks' => true,
        ]);
        $this->hasMany('SecurityServiceMaintenanceDates', [
            'saveStrategy' => 'replace',
        ]);
        $this->hasMany('SecurityServiceIssues', [
            'foreignKey' => 'foreign_key',
            'conditions' => [
                'SecurityServiceIssues.model' => 'SecurityServices',
            ],
            'dependent' => true,
            'cascadeCallbacks' => true,
        ]);

        $this->belongsTo('SecurityServiceTypes');
        $this->belongsToMany('ServiceContracts');
        $this->belongsToMany('SecurityPolicies');
        $this->belongsToMany('Risks');
        $this->belongsToMany('ThirdPartyRisks');
        $this->belongsToMany('BusinessContinuities');
        $this->belongsToMany('SecurityIncidents');
        $this->belongsToMany('DataAssets');
        $this->belongsToMany('ComplianceManagements');
        $this->belongsToMany('Projects');
        $this->belongsToMany('Goals');

        $this->addBehavior('Timestamp');
        $this->addBehavior('AccessControl.AccessControl');
        $this->addBehavior('AccessControl.Visualisation');
        $this->addBehavior('FieldData.FieldData');
        $this->addBehavior('AdvancedFilters.AdvancedFilters');
        $this->addBehavior('UserFields.UserFields', [
            'fields' => [
                'ServiceOwners',
                'Collaborators',
                'AuditOwners',
                'AuditEvidenceOwners',
                'MaintenanceOwners',
            ],
        ]);
        $this->addBehavior('CustomRoles.CustomRoles');
        $this->addBehavior('Macros.Macro');
        $this->addBehavior('Auditable', [
            'ignore' => [
                'audits_all_done', 'audits_not_all_done', 'audits_last_missing', 'audits_last_passed', 'audit_improvements',
                'audits_status', 'maintenances_all_done', 'maintenances_not_all_done', 'maintenances_last_missing',
                'maintenances_last_passed', 'ongoing_security_incident', 'control_with_issues', 'ongoing_corrective_actions',
            ],
            'associations' => [
                'ServiceOwners',
                'Collaborators',
                'AuditOwners',
                'AuditEvidenceOwners',
                'MaintenanceOwners',
                'ServiceContracts',
                'SecurityPolicies',
                'Projects',
                'Classifications' => [
                    'field' => 'title',
                ],
            ],
        ]);
        $this->addBehavior('Trash'); // place after Auditable
        $this->addBehavior('Comments.Comments');
        $this->addBehavior('Attachments.Attachments');
        $this->addBehavior('Widget.Widget');
        $this->addBehavior('DynamicStatus.DynamicStatus');
        $this->addBehavior('ImportTool.ImportTool');
        $this->addBehavior('Taggable.Taggable', [
            'fields' => [
                'Classifications',
            ],
        ]);
        $this->addBehavior('YearlyCalendar.YearlyCalendar', [
            'scopes' => [
                'audit' => [
                    'storageTable' => $this->getAssociation('SecurityServiceAuditDates'),
                ],
                'maintenance' => [
                    'storageTable' => $this->getAssociation('SecurityServiceMaintenanceDates'),
                    'typeLabel' => __('Maintenance Dates'),
                    'types' => [
                        YearlyCalendarBehavior::CALENDAR_TYPE_NO_DATES => __('No Maintenance Required'),
                        YearlyCalendarBehavior::CALENDAR_TYPE_SPECIFIC_DATES => __('Maintenance Required'),
                    ],
                ],
            ],
        ]);
        $this->addBehavior('SubSection.SubSection', [
            'children' => [
                'SecurityServiceAudits',
                'SecurityServiceMaintenances',
                'SecurityServiceIssues',
            ],
        ]);
        $this->addBehavior('RestrictDelete.RestrictDelete', [
            'associations' => [
                'Risks',
                'ThirdPartyRisks',
                'BusinessContinuities',
            ],
        ]);
        $this->addBehavior('SectionInfo.SectionInfo');
        $this->addBehavior('FormOrganization.FormOrganization');
        $this->addBehavior('IntegrityCheck.IntegrityCheck');

        $this->addOptionalBehavior('CustomFields.CustomFields', [
            'moduleRelationships' => [
                'Legals',
                'BusinessUnits',
                'Processes',
                'ThirdParties',
                'Assets',
                'BusinessContinuityPlans',
                'SecurityPolicies',
                'PolicyExceptions',
                'Risks',
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
        $this->addOptionalBehavior('CustomLabels.CustomLabels');
        $this->addOptionalBehavior('NotificationSystem.NotificationSystem');
        $this->addOptionalBehavior('Reports.Report');
        $this->addOptionalBehavior('Api.Api');
        $this->addOptionalBehavior('ActivityLog.ActivityLog', [
            'listenTo' => [
                'security_service_audits',
                'security_service_maintenances',
                'name',
                'objective',
                'security_service_type_id',
                'documentation_url',
                'classifications',
                'audit_calendar_type',
                'audit_metric_description',
                'audit_success_criteria',
                'maintenance_calendar_type',
                'maintenance_metric_description',
                'opex',
                'capex',
                'resource_utilization',
                'service_contracts',
                'security_policies',
                'projects',
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
            ->notEmptyString('name')
            ->maxLength('title', 255);

        $validator
            ->url('documentation_url')
            ->allowEmptyString('documentation_url');

        $validator
            ->add('opex', 'numeric', [
                'on' => function ($context) {
                    $field = $context['field'];

                    return isset($context['data'][$field])
                        && $context['data'][$field] !== null
                        && $context['data'][$field] !== '';
                },
            ])
            ->allowEmptyFor('opex');

        $validator
            ->add('capex', 'numeric', [
                'on' => function ($context) {
                    $field = $context['field'];

                    return isset($context['data'][$field])
                        && $context['data'][$field] !== null
                        && $context['data'][$field] !== '';
                },
            ])
            ->allowEmptyFor('capex');

        $validator
            ->add('resource_utilization', 'numeric', [
                'on' => function ($context) {
                    $field = $context['field'];

                    return isset($context['data'][$field])
                        && $context['data'][$field] !== null
                        && $context['data'][$field] !== '';
                },
            ])
            ->allowEmptyFor('resource_utilization');

        $validator
            ->notEmptyString('security_service_type_id')
            ->inList('security_service_type_id', array_keys(self::types()));

        $validator
            ->add('audit_metric_description', 'notBlank', [
                'message' => __('This field cannot be left empty'),
                'on' => function ($context) {
                    return $this->auditCalendarEnabled($context);
                },
            ]);

        $validator
            ->add('audit_success_criteria', 'notBlank', [
                'message' => __('This field cannot be left empty'),
                'on' => function ($context) {
                    return $this->auditCalendarEnabled($context);
                },
            ]);

        $validator
            ->notEmptyArray('collaborators');

        $validator
            ->notEmptyArray('service_owners');

        $validator
            ->add('audit_owners', 'multiple', [
                'message' => __('This field cannot be left empty'),
                'on' => function ($context) {
                    return $this->auditCalendarEnabled($context);
                },
            ]);

        $validator
            ->add('audit_evidence_owners', 'multiple', [
                'message' => __('This field cannot be left empty'),
                'on' => function ($context) {
                    return $this->auditCalendarEnabled($context);
                },
            ]);

        $validator
            ->add('maintenance_metric_description', 'notBlank', [
                'message' => __('This field cannot be left empty'),
                'on' => function ($context) {
                    return $this->maintenanceCalendarEnabled($context);
                },
            ]);

        $validator
            ->add('maintenance_owners', 'multiple', [
                'message' => __('This field cannot be left empty'),
                'on' => function ($context) {
                    return $this->maintenanceCalendarEnabled($context);
                },
            ]);

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
        $this->validationBase($validator);

        $validator
            ->add('security_service_audit_dates_import', 'date', [
                'rule' => [$this, 'validateImportCalendarDates'],
                'message' => __('Invalid date format.'),
            ]);

        $validator
            ->add('security_service_maintenance_dates_import', 'date', [
                'rule' => [$this, 'validateImportCalendarDates'],
                'message' => __('Invalid date format.'),
            ]);

        $validator
            ->add('audit_calendar_type', 'specificAuditDates', [
                'rule' => [$this, 'validateSpecificAuditDates'],
                'message' => __('You need to add at least one audit date.'),
            ]);

        $validator
            ->add('maintenance_calendar_type', 'specificMaintenanceDates', [
                'rule' => [$this, 'validateSpecificMaintenanceDates'],
                'message' => __('You need to add at least one maintenance date.'),
            ]);

        return $validator;
    }

    /**
     * Validate specific audit dates.
     *
     * @param mixed $check Check.
     * @param array $context Context.
     * @return bool
     */
    public function validateSpecificAuditDates($check, array $context): bool
    {
        if ($check && is_numeric($check) && (int)$check === YearlyCalendarBehavior::CALENDAR_TYPE_SPECIFIC_DATES) {
            $data = $context['data'];

            if (!isset($data['security_service_audit_dates']) || !$data['security_service_audit_dates']) {
                return false;
            }
        }

        return true;
    }

    /**
     * Validate specific maintenance dates.
     *
     * @param mixed $check Check.
     * @param array $context Context.
     * @return bool
     */
    public function validateSpecificMaintenanceDates($check, array $context): bool
    {
        if ($check && is_numeric($check) && (int)$check === YearlyCalendarBehavior::CALENDAR_TYPE_SPECIFIC_DATES) {
            $data = $context['data'];

            if (!isset($data['security_service_maintenance_dates']) || !$data['security_service_maintenance_dates']) {
                return false;
            }
        }

        return true;
    }

    /**
     * BulkActions validation rules.
     *
     * @param \Cake\Validation\Validator $validator Validator instance.
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
            ->requirePresence('name')
            ->requirePresence('objective')
            ->requirePresence('documentation_url')
            ->requirePresence('security_service_type_id')
            ->requirePresence('classifications')
            ->array('classifications')
            ->requirePresence('service_owners')
            ->array('service_owners')
            ->requirePresence('collaborators')
            ->array('collaborators')
            ->requirePresence('opex')
            ->requirePresence('capex')
            ->requirePresence('resource_utilization')
            ->requirePresence('service_contracts')
            ->array('service_contracts')
            ->requirePresence('security_policies')
            ->array('security_policies')
            ->add('security_policies', 'integerBelongsToMany', [
                'provider' => 'app',
            ])
            ->requirePresence('projects')
            ->array('projects')
            ->requirePresence('security_service_audit_dates')
            ->array('security_service_audit_dates')
            ->requirePresence('audit_metric_description')
            ->requirePresence('audit_success_criteria')
            ->requirePresence('audit_owners')
            ->array('audit_owners')
            ->requirePresence('audit_evidence_owners')
            ->array('audit_evidence_owners')
            ->requirePresence('security_service_maintenance_dates')
            ->array('security_service_maintenance_dates')
            ->requirePresence('maintenance_metric_description')
            ->requirePresence('maintenance_owners')
            ->array('maintenance_owners');

        return $validator;
    }

    public function validateImportCalendarDates($check, $context): bool
    {
        if ($check) {
            foreach ($check as $date) {
                $parts = explode('-', $date);
                if (count($parts) !== 2) {
                    return false;
                }

                $date = $parts[0] . '-' . $parts[1] . '-' . date('Y');
                if (!Validation::date($date, 'dmy')) {
                    return false;
                }
            }
        }

        return true;
    }

    public function auditCalendarEnabled($context): bool
    {
        return isset($context['data']['audit_calendar_type']) && $context['data']['audit_calendar_type'] != YearlyCalendarBehavior::CALENDAR_TYPE_NO_DATES;
    }

    public function maintenanceCalendarEnabled($context): bool
    {
        return isset($context['data']['maintenance_calendar_type']) && $context['data']['maintenance_calendar_type'] != YearlyCalendarBehavior::CALENDAR_TYPE_NO_DATES;
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
            ->text('name', [
                'label' => __('Name'),
                'description' => __('For Example: Account Reviews, Patching, Awareness Reviews, Etc.'),
                'extensions' => [
                    'Macros.Macro',
                    'InlineEdit.InlineEdit',
                    'CustomLabels.CustomLabels' => [
                        'label' => true,
                        'description' => true,
                    ],
                ],
            ])
            ->textarea('objective', [
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
            ->textarea('documentation_url', [
                'label' => __('Documentation URL'),
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
            ->select('SecurityServiceTypes', [
                'label' => __('Status'),
                'description' => __('Only Internal Controls in Production status can be linked to Risks, Compliance Requirements and Data Flows.'),//phpcs:ignore
                'options' => [$this, 'types'],
                'extensions' => [
                    'Macros.Macro',
                    'InlineEdit.InlineEdit',
                    'CustomLabels.CustomLabels' => [
                        'label' => true,
                        'description' => true,
                    ],
                ],
            ])
            ->select('security_service_type_id', [
                'label' => __('Status'),
                'description' => __('Only Internal Controls in Production status can be linked to Risks, Compliance Requirements and Data Flows.'),//phpcs:ignore
                'options' => [$this, 'types'],
                'extensions' => [
                    'Macros.Macro',
                    'InlineEdit.InlineEdit',
                    'CustomLabels.CustomLabels' => [
                        'label' => true,
                        'description' => true,
                    ],
                ],
            ])
            ->taggable('Classifications', [
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
            ->userField('ServiceOwners', [
                'label' => __('GRC Contact'),
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
            ->userField('Collaborators', [
                'label' => __('Control Operator Contact'),
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
            ->number('opex', [
                'label' => __('Cost (OPEX)'),
                'description' => __('The amount of money it costs to operate this Control.'),
                'extensions' => [
                    'Macros.Macro',
                    'InlineEdit.InlineEdit',
                    'CustomLabels.CustomLabels' => [
                        'label' => true,
                        'description' => true,
                    ],
                ],
            ])
            ->number('capex', [
                'label' => __('Cost (CAPEX)'),
                'description' => __('The amount of money it costs to implement this control.'),
                'extensions' => [
                    'Macros.Macro',
                    'InlineEdit.InlineEdit',
                    'CustomLabels.CustomLabels' => [
                        'label' => true,
                        'description' => true,
                    ],
                ],
            ])
            ->number('resource_utilization', [
                'label' => __('Resource Utilization'),
                'description' => __('The amount of time in hours it takes to test this control.'),
                'extensions' => [
                    'Macros.Macro',
                    'InlineEdit.InlineEdit',
                    'CustomLabels.CustomLabels' => [
                        'label' => true,
                        'description' => true,
                    ],
                ],
            ])
            ->multiselect('ServiceContracts', [
                'label' => __('Support Contracts'),
                'options' => [$this->ServiceContracts, 'getList'],
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
            ->multiselect('SecurityPolicies', [
                'label' => __('Related Policies'),
                'options' => [$this->SecurityPolicies, 'getList'],
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
                'label' => __('Related Projects'),
                'options' => [$this->Projects, 'getList'],
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
            ->multiselect('SecurityServiceAudits', [
                'label' => __('Security Service Audit'),
                'extensions' => [
                    'Macros.Macro',
                ],
            ])
            ->userField('AuditOwners', [
                'label' => __('Audit Owner'),
                'extensions' => [
                    'Macros.Macro',
                    'InlineEdit.InlineEdit',
                    'CustomLabels.CustomLabels' => [
                        'label' => true,
                        'description' => true,
                    ],
                ],
            ])
            ->userField('AuditEvidenceOwners', [
                'label' => __('Audit Evidence Owner'),
                'extensions' => [
                    'Macros.Macro',
                    'InlineEdit.InlineEdit',
                    'CustomLabels.CustomLabels' => [
                        'label' => true,
                        'description' => true,
                    ],
                ],
            ])
            ->textarea('audit_metric_description', [
                'label' => __('Audit Methodology'),
                'description' => __('Describe what evidence and analysis will be used to audit this control'),
                'extensions' => [
                    'Macros.Macro',
                    'InlineEdit.InlineEdit',
                    'CustomLabels.CustomLabels' => [
                        'label' => true,
                        'description' => true,
                    ],
                ],
            ])
            ->textarea('audit_success_criteria', [
                'label' => __('Audit Success Criteria'),
                'description' => __('Describe what is required to Pass this Audit'),
                'extensions' => [
                    'Macros.Macro',
                    'InlineEdit.InlineEdit',
                    'CustomLabels.CustomLabels' => [
                        'label' => true,
                        'description' => true,
                    ],
                ],
            ])
            ->multiselect('SecurityServiceMaintenances', [
                'label' => __('Security Service Maintenance'),
                'extensions' => [
                    'Macros.Macro',
                ],
            ])
            ->userField('MaintenanceOwners', [
                'label' => __('Maintenance Owner'),
                'extensions' => [
                    'Macros.Macro',
                    'InlineEdit.InlineEdit',
                    'CustomLabels.CustomLabels' => [
                        'label' => true,
                        'description' => true,
                    ],
                ],
            ])
            ->textarea('maintenance_metric_description', [
                'label' => __('Maintenance Task'),
                'description' => __('Describe what maintenance this control requires'),
                'extensions' => [
                    'Macros.Macro',
                    'InlineEdit.InlineEdit',
                    'CustomLabels.CustomLabels' => [
                        'label' => true,
                        'description' => true,
                    ],
                ],
            ])
            ->multiselect('SecurityServiceIssues', [
                'label' => __('Issues'),
                'extensions' => [
                    'Macros.Macro',
                ],
            ])
            ->multiselect('Risks', [
                'label' => __('Asset Risks'),
                'extensions' => [
                    'Macros.Macro',
                ],
            ])
            ->multiselect('ThirdPartyRisks', [
                'label' => __('Third Party Risks'),
                'extensions' => [
                    'Macros.Macro',
                ],
            ])
            ->multiselect('BusinessContinuities', [
                'label' => __('Business Risks'),
                'extensions' => [
                    'Macros.Macro',
                ],
            ])
            ->multiselect('SecurityIncidents', [
                'label' => __('Security Incidents'),
                'extensions' => [
                    'Macros.Macro',
                ],
            ])
            ->multiselect('DataAssets', [
                'label' => __('Data Asset Flows'),
                'extensions' => [
                    'Macros.Macro',
                ],
            ])
            ->multiselect('ComplianceManagements', [
                'label' => __('Compliance Managements'),
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
                'subject' => $collection->get('name'),
            ])
            ->addWidget([
                'order' => true,
                'optional' => true,
                'subject' => $collection->get('objective'),
            ])
            ->addWidget([
                'order' => true,
                'optional' => true,
                'subject' => $collection->get('ServiceOwners'),
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
                'subject' => $collection->get('Collaborators'),
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
                'subject' => $collection->get('SecurityPolicies'),
                'insertOptions' => [
                    'listeners' => [
                        'QuickAdd.QuickAdd' => [
                            'targetTable' => $this->SecurityPolicies,
                        ],
                    ],
                    'empty' => true,
                ],
            ])
            ->addWidget([
                'order' => true,
                'optional' => true,
                'subject' => $collection->get('Projects'),
                'insertOptions' => [
                    'listeners' => [
                        'QuickAdd.QuickAdd' => [
                            'targetTable' => $this->Projects,
                        ],
                    ],
                    'empty' => true,
                ],
            ])
            ->addWidget([
                'order' => true,
                'subject' => $collection->get('security_service_type_id'),
                'insertOptions' => [
                    'empty' => true,
                ],
            ])
            ->addWidget([
                'order' => true,
                'optional' => true,
                'subject' => $collection->get('Classifications'),
                'insertOptions' => [
                    'empty' => true,
                ],
                'settings' => [
                    'hidden' => true,
                ],
            ])
            ->addWidget([
                'order' => true,
                'optional' => true,
                'subject' => $collection->get('documentation_url'),
                'settings' => [
                    'hidden' => true,
                ],
            ])
            ->addWidget([
                'order' => true,
                'optional' => true,
                'subject' => $collection->get('opex'),
                'settings' => [
                    'hidden' => true,
                ],
            ])
            ->addWidget([
                'order' => true,
                'optional' => true,
                'subject' => $collection->get('capex'),
                'settings' => [
                    'hidden' => true,
                ],
            ])
            ->addWidget([
                'order' => true,
                'optional' => true,
                'subject' => $collection->get('resource_utilization'),
                'settings' => [
                    'hidden' => true,
                ],
            ])
            ->addWidget([
                'order' => true,
                'optional' => true,
                'subject' => $collection->get('ServiceContracts'),
                'insertOptions' => [
                    'listeners' => [
                        'QuickAdd.QuickAdd' => [
                            'targetTable' => $this->ServiceContracts,
                        ],
                    ],
                    'empty' => true,
                ],
                'settings' => [
                    'hidden' => true,
                ],
            ]);

        $auditCalendarScope = $this->getBehavior('YearlyCalendar')->getScope('audit');

        $formOrganizer
            ->addWidget([
                'className' => GroupWidget::class,
                'name' => 'group__audits',
                'order' => true,
                'label' => __('Audits'),
            ])
            ->addWidget([
                'className' => FormOrganizerWidget::class,
                'name' => 'audits_calendar',
                'order' => true,
                'label' => __('Audits Calendar Widget'),
                'insert' => function (FormInterface $form) use ($auditCalendarScope) {
                    /** @var \FieldData\Form\TabsForm $form */
                    $form
                        ->add($auditCalendarScope);
                },
            ])
            ->addWidget([
                'order' => true,
                'subject' => $collection->get('audit_metric_description'),
                'insert' => function (FormInterface $form) use ($collection) {
                    /** @var \FieldData\Form\TabsForm $form */
                    $entity = $form->getContext()->entity();
                    $auditReadonlyListeners = [];
                    if ($entity->get('audit_calendar_type') == YearlyCalendarBehavior::CALENDAR_TYPE_NO_DATES) {
                        $auditReadonlyListeners[] = 'ReadOnly';
                    }
                    $form
                        ->add($collection->get('audit_metric_description'), [
                            'listeners' => $auditReadonlyListeners,
                        ]);
                },
            ])
            ->addWidget([
                'order' => true,
                'subject' => $collection->get('audit_success_criteria'),
                'insert' => function (FormInterface $form) use ($collection) {
                    /** @var \FieldData\Form\TabsForm $form */
                    $entity = $form->getContext()->entity();
                    $auditReadonlyListeners = [];
                    if ($entity->get('audit_calendar_type') == YearlyCalendarBehavior::CALENDAR_TYPE_NO_DATES) {
                        $auditReadonlyListeners[] = 'ReadOnly';
                    }
                    $form
                        ->add($collection->get('audit_success_criteria'), [
                            'listeners' => $auditReadonlyListeners,
                        ]);
                },
            ])
            ->addWidget([
                'order' => true,
                'subject' => $collection->get('AuditOwners'),
                'insert' => function (FormInterface $form) use ($collection) {
                    /** @var \FieldData\Form\TabsForm $form */
                    $entity = $form->getContext()->entity();
                    $auditReadonlyListeners = [];
                    if ($entity->get('audit_calendar_type') == YearlyCalendarBehavior::CALENDAR_TYPE_NO_DATES) {
                        $auditReadonlyListeners[] = 'ReadOnly';
                    }
                    $form
                        ->add($collection->get('AuditOwners'), [
                            'listeners' => array_merge([
                                'QuickAdd.QuickAdd' => [
                                    'targetTable' => $this->getTableLocator()->get('Users'),
                                ],
                            ], $auditReadonlyListeners),
                            'empty' => true,
                        ]);
                },
            ])
            ->addWidget([
                'order' => true,
                'subject' => $collection->get('AuditEvidenceOwners'),
                'insert' => function (FormInterface $form) use ($collection) {
                    /** @var \FieldData\Form\TabsForm $form */
                    $entity = $form->getContext()->entity();
                    $auditReadonlyListeners = [];
                    if ($entity->get('audit_calendar_type') == YearlyCalendarBehavior::CALENDAR_TYPE_NO_DATES) {
                        $auditReadonlyListeners[] = 'ReadOnly';
                    }
                    $form
                        ->add($collection->get('AuditEvidenceOwners'), [
                            'listeners' => array_merge([
                                'QuickAdd.QuickAdd' => [
                                    'targetTable' => $this->getTableLocator()->get('Users'),
                                ],
                            ], $auditReadonlyListeners),
                            'empty' => true,
                        ]);
                },
            ]);

        $maintenanceCalendarScope = $this->getBehavior('YearlyCalendar')->getScope('maintenance');

        $formOrganizer
            ->addWidget([
                'className' => GroupWidget::class,
                'name' => 'group__maintenances',
                'order' => true,
                'label' => __('Maintenances'),
            ])
            ->addWidget([
                'className' => FormOrganizerWidget::class,
                'name' => 'maintenances_calendar',
                'order' => true,
                'label' => __('Maintenances Calendar Widget'),
                'insert' => function (FormInterface $form) use ($maintenanceCalendarScope) {
                    /** @var \FieldData\Form\TabsForm $form */
                    $form
                        ->add($maintenanceCalendarScope);
                },
            ])
            ->addWidget([
                'order' => true,
                'subject' => $collection->get('maintenance_metric_description'),
                'insert' => function (FormInterface $form) use ($collection) {
                    /** @var \FieldData\Form\TabsForm $form */
                    $entity = $form->getContext()->entity();
                    $maintenanceReadonlyListeners = [];
                    if ($entity->get('maintenance_calendar_type') == YearlyCalendarBehavior::CALENDAR_TYPE_NO_DATES) {
                        $maintenanceReadonlyListeners[] = 'ReadOnly';
                    }
                    $form
                        ->add($collection->get('maintenance_metric_description'), [
                            'listeners' => $maintenanceReadonlyListeners,
                        ]);
                },
            ])
            ->addWidget([
                'order' => true,
                'subject' => $collection->get('MaintenanceOwners'),
                'insert' => function (FormInterface $form) use ($collection) {
                    /** @var \FieldData\Form\TabsForm $form */
                    $entity = $form->getContext()->entity();
                    $maintenanceReadonlyListeners = [];
                    if ($entity->get('maintenance_calendar_type') == YearlyCalendarBehavior::CALENDAR_TYPE_NO_DATES) {
                        $maintenanceReadonlyListeners[] = 'ReadOnly';
                    }
                    $form
                        ->add($collection->get('MaintenanceOwners'), [
                            'listeners' => array_merge([
                                'QuickAdd.QuickAdd' => [
                                    'targetTable' => $this->getTableLocator()->get('Users'),
                                ],
                            ], $maintenanceReadonlyListeners),
                            'empty' => true,
                        ]);
                },
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

    /**
     * Bulk form organization config.
     *
     * @param \Cake\Event\EventInterface $event Event.
     * @param \FormOrganization\FormOrganizer $formOrganizer FormOrganizer.
     * @return void
     */
    public function buildOrganizerBulk(EventInterface $event, FormOrganizer $formOrganizer): void
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
                'order' => false,
                'subject' => $collection->get('name'),
                'insertOptions' => [
                    'listeners' => [
                        'BulkActions.BulkActions' => [
                            'options' => BulkActionsListener::FLAG_SKIP_CLEAR_OPTION,
                        ],
                    ],
                ],
            ])
            ->addWidget([
                'order' => true,
                'optional' => true,
                'subject' => $collection->get('objective'),
            ])
            ->addWidget([
                'order' => true,
                'subject' => $collection->get('ServiceOwners'),
                'insertOptions' => [
                    'empty' => true,
                ],
            ])
            ->addWidget([
                'order' => true,
                'subject' => $collection->get('Collaborators'),
                'insertOptions' => [
                    'empty' => true,
                ],
            ])
            ->addWidget([
                'order' => true,
                'subject' => $collection->get('SecurityPolicies'),
                'insertOptions' => [
                    'empty' => true,
                ],
            ])
            ->addWidget([
                'order' => true,
                'optional' => true,
                'subject' => $collection->get('Projects'),
                'insertOptions' => [
                    'empty' => true,
                ],
            ])
            ->addWidget([
                'order' => true,
                'subject' => $collection->get('security_service_type_id'),
                'insertOptions' => [
                    'listeners' => [
                        'BulkActions.BulkActions' => [
                            'options' => BulkActionsListener::FLAG_SKIP_CLEAR_OPTION,
                        ],
                    ],
                    'empty' => true,
                ],
            ])
            ->addWidget([
                'order' => true,
                'optional' => true,
                'subject' => $collection->get('Classifications'),
                'insertOptions' => [
                    'empty' => true,
                ],
                'settings' => [
                    'hidden' => true,
                ],
            ])
            ->addWidget([
                'order' => true,
                'optional' => true,
                'subject' => $collection->get('documentation_url'),
                'settings' => [
                    'hidden' => true,
                ],
            ])
            ->addWidget([
                'order' => true,
                'optional' => true,
                'subject' => $collection->get('opex'),
                'settings' => [
                    'hidden' => true,
                ],
                'insertOptions' => [
                    'listeners' => [
                        'BulkActions.BulkActions' => [
                            'options' => BulkActionsListener::FLAG_SKIP_CLEAR_OPTION,
                        ],
                    ],
                ],
            ])
            ->addWidget([
                'order' => true,
                'optional' => true,
                'subject' => $collection->get('capex'),
                'settings' => [
                    'hidden' => true,
                ],
                'insertOptions' => [
                    'listeners' => [
                        'BulkActions.BulkActions' => [
                            'options' => BulkActionsListener::FLAG_SKIP_CLEAR_OPTION,
                        ],
                    ],
                ],
            ])
            ->addWidget([
                'order' => true,
                'optional' => true,
                'subject' => $collection->get('resource_utilization'),
                'settings' => [
                    'hidden' => true,
                ],
                'insertOptions' => [
                    'listeners' => [
                        'BulkActions.BulkActions' => [
                            'options' => BulkActionsListener::FLAG_SKIP_CLEAR_OPTION,
                        ],
                    ],
                ],
            ])
            ->addWidget([
                'order' => true,
                'optional' => true,
                'subject' => $collection->get('ServiceContracts'),
                'settings' => [
                    'hidden' => true,
                ],
                'insertOptions' => [
                    'empty' => true,
                ],
            ]);
    }

    public function formBulkActions(FormInterface $form): FormInterface
    {
        /** @var \FormOrganization\Model\Behavior\FormOrganizationBehavior $formOrganizationBehavior */
        $formOrganizationBehavior = $this->getBehavior('FormOrganization');

        $organizer = $formOrganizationBehavior->getOrganizer('bulk');
        $organizer->organize($form);

        return $form;
    }

    public function buildAdvancedFilters(EventInterface $event, FilterConfigurationBuilder $config): void
    {
        $config
            // general tab
            ->group('general', [
                'name' => __('General'),
            ])
            ->counterField('SecurityServiceAudits_count', [
                'label' => __('Audits'),
            ])
            ->counterField('SecurityServiceMaintenances_count', [
                'label' => __('Maintenances'),
            ])
            ->counterField('SecurityServiceIssues_count', [
                'label' => __('Issues'),
            ])
            ->nonFilterableField('id')
            ->textField('name', [
                'showDefault' => true,
            ])
            ->textField('objective', [
                'showDefault' => true,
            ])
            ->userField('ServiceOwner', 'ServiceOwners', [
                'count' => true,
                'showDefault' => true,
            ])
            ->userField('Collaborator', 'Collaborators', [
                'count' => true,
                'showDefault' => true,
            ])
            ->multipleSelectField('Classification-name', [$this, 'getTagsList'], [
                'fieldData' => 'Classifications.title',
                'label' => __('Tags'),
            ])
            ->textField('documentation_url')
            ->multipleSelectField('security_service_type_id', [$this, 'types'])
            ->numberField('opex', [
                'label' => __('Opex'),
            ])
            ->numberField('capex', [
                'label' => __('Capex'),
            ])
            ->numberField('resource_utilization')
            ->dynamicStatusField('DynamicStatus_SecurityServiceIssue-open', 'SecurityServiceIssue-open')
            ->dynamicStatusField('DynamicStatus_doing-nothing', 'doing-nothing')
            // security service audits tab
            ->group('security-service-audits', [
                'name' => __('Audit'),
            ])
            ->dateField('SecurityServiceAudit-planned_date', [
                'fieldData' => 'SecurityServiceAudits.planned_date',
                'label' => __('Audit Date'),
            ])
            ->textField('audit_metric_description')
            ->textField('audit_success_criteria')
            ->userField('AuditOwner', 'AuditOwners', [
                'count' => true,
            ])
            ->userField('AuditEvidenceOwner', 'AuditEvidenceOwners', [
                'count' => true,
            ])
            ->dynamicStatusField('DynamicStatus_current_audit_failed', 'current_audit_failed')
            ->dynamicStatusField('DynamicStatus_current_audit_expired', 'current_audit_expired')
            ->dynamicStatusField('DynamicStatus_audits-empty', 'audits-empty')
            // security service maintenances tab
            ->group('security-service-maintenances', [
                'name' => __('Maintenances'),
            ])
            ->dateField('SecurityServiceMaintenance-planned_date', [
                'fieldData' => 'SecurityServiceMaintenances.planned_date',
                'label' => __('Maintenance Date'),
            ])
            ->textField('maintenance_metric_description')
            ->userField('MaintenanceOwner', 'MaintenanceOwners', [
                'count' => true,
            ])
            ->dynamicStatusField('DynamicStatus_current_maintenance_failed', 'current_maintenance_failed')
            ->dynamicStatusField('DynamicStatus_current_maintenance_expired', 'current_maintenance_expired');

        // security policies tab
        $this->SecurityPolicies->relatedFilters($config);
        $config->field('SecurityPolicy', [
            'showDefault' => true,
        ]);

        // risks tab
        $this->Risks->relatedFilters($config);
        $config->field('Risk', [
            'showDefault' => true,
        ]);

        // third party risks tab
        $this->ThirdPartyRisks->relatedFilters($config);
        $config->field('ThirdPartyRisk', [
            'showDefault' => true,
        ]);

        // business continuities tab
        $this->BusinessContinuities->relatedFilters($config);
        $config->field('BusinessContinuity', [
            'showDefault' => true,
        ]);

        // compliance managements tab
        $this->ComplianceManagements->relatedFilters($config);
        $config->field('CompliancePackage-compliance_package_regulator_id', [
            'showDefault' => true,
        ]);

        // security incidents tab
        $this->SecurityIncidents->relatedFilters($config);

        // data assets tab
        $config
            ->group('data-assets', [
                'name' => __('Data Flow Analysis'),
            ])
            ->multipleSelectField('DataAssetInstance-asset_id', [$this->getTableLocator()->get('Assets'), 'getList'], [
                'count' => true,
                'label' => __('Asset'),
                'findField' => 'DataAssets.DataAssetInstances.asset_id',
                'fieldData' => 'DataAssets.DataAssetInstances.Assets.id',
            ])
            ->multipleSelectField('DataAsset', [$this->DataAssets, 'getList'], [
                'fieldData' => 'DataAssets',
                'showDefault' => true,
                'count' => true,
            ])
            ->multipleSelectField('DataAsset-data_asset_status_id', [$this->DataAssets, 'statuses'], [
                'fieldData' => 'DataAssets.data_asset_status_id',
                'label' => __('Data Asset Flow Type'),
            ]);

        // projects tab
        $this->Projects->relatedFilters($config);

        // service contracts tab
        $this->ServiceContracts->relatedFilters($config);

        $config
            // other tab
            ->group('other', [
                'name' => __('Other'),
            ])
            ->dateField('created', [
                'label' => __('Created on'),
            ])
            ->dateField('modified', [
                'label' => __('Last Updated'),
                'findField' => $this->aliasField('edited'),
                'fieldData' => 'edited',
            ]);
    }

    public function getAdvancedFilterSeed(SeedCollection $collection): SeedCollection
    {
        $collection->add('AllItems')
            ->addParam('Risk__count', 1)
            ->addParam('ThirdPartyRisk__count', 1)
            ->addParam('BusinessContinuity__count', 1)
            ->addParam('CompliancePackage-compliance_package_regulator_id__count', 1)
            ->addParam('DataAsset__count', 1);

        $newComments = $collection->add('Comments.NewComments');
        $newComments->showOnly([$this->getDisplayField(), 'comment_message']);

        $newAttachments = $collection->add('Attachments.NewAttachments');
        $newAttachments->showOnly([$this->getDisplayField(), 'attachment_filename']);

        $newItems = $collection->add('NewItems');
        $newItems->showOnly([$this->getDisplayField()]);

        $updatedItems = $collection->add('UpdatedItems');
        $updatedItems->showOnly([$this->getDisplayField()]);

        $collection->add('ControlIssues')
            ->addParam('Risk__count', 1)
            ->addParam('ThirdPartyRisk__count', 1)
            ->addParam('BusinessContinuity__count', 1)
            ->addParam('CompliancePackage-compliance_package_regulator_id__count', 1)
            ->addParam('DataAsset__count', 1);

        $collection->add('CurrentAuditExpired')
            ->addParam('Risk__count', 1)
            ->addParam('ThirdPartyRisk__count', 1)
            ->addParam('BusinessContinuity__count', 1)
            ->addParam('CompliancePackage-compliance_package_regulator_id__count', 1)
            ->addParam('DataAsset__count', 1);

        $collection->add('CurrentAuditFailed')
            ->addParam('Risk__count', 1)
            ->addParam('ThirdPartyRisk__count', 1)
            ->addParam('BusinessContinuity__count', 1)
            ->addParam('CompliancePackage-compliance_package_regulator_id__count', 1)
            ->addParam('DataAsset__count', 1);

        $collection->add('CurrentMaintenanceExpired')
            ->addParam('Risk__count', 1)
            ->addParam('ThirdPartyRisk__count', 1)
            ->addParam('BusinessContinuity__count', 1)
            ->addParam('CompliancePackage-compliance_package_regulator_id__count', 1)
            ->addParam('DataAsset__count', 1);

        $collection->add('CurrentMaintenanceFailed')
            ->addParam('Risk__count', 1)
            ->addParam('ThirdPartyRisk__count', 1)
            ->addParam('BusinessContinuity__count', 1)
            ->addParam('CompliancePackage-compliance_package_regulator_id__count', 1)
            ->addParam('DataAsset__count', 1);

        $collection->add('SecurityServicesPoliciesEmpty')
            ->addParam('Risk__count', 1)
            ->addParam('ThirdPartyRisk__count', 1)
            ->addParam('BusinessContinuity__count', 1)
            ->addParam('CompliancePackage-compliance_package_regulator_id__count', 1)
            ->addParam('DataAsset__count', 1);

        $collection->add('SecurityServicesAuditsEmpty')
            ->addParam('Risk__count', 1)
            ->addParam('ThirdPartyRisk__count', 1)
            ->addParam('BusinessContinuity__count', 1)
            ->addParam('CompliancePackage-compliance_package_regulator_id__count', 1)
            ->addParam('DataAsset__count', 1);

        $collection->add('SecurityServicesDoingNothing')
            ->addParam('Risk__count', 1)
            ->addParam('ThirdPartyRisk__count', 1)
            ->addParam('BusinessContinuity__count', 1)
            ->addParam('CompliancePackage-compliance_package_regulator_id__count', 1)
            ->addParam('DataAsset__count', 1);

        return $collection;
    }

    public function relatedFilters(FilterConfigurationBuilder $config): void
    {
        $config
            ->group('security-services', [
                'name' => $this->getSection()->getSingular(),
            ])
            ->multipleSelectField('SecurityService', [$this, 'getList'], [
                'fieldData' => 'SecurityServices',
                'count' => true,
                'label' => $this->getSection()->getSingular(),
            ])
            ->textField('SecurityService-objective', [
                'fieldData' => 'SecurityServices.objective',
                'label' => __('Internal Control Description'),
            ]);
    }

    public function buildDynamicStatusConfig(EventInterface $event, StatusConfigurationBuilder $config): void
    {
        $config
            // fields
            ->group('fields', __('Fields'))
            ->text('name')
            ->text('objective')
            ->text('documentation_url')
            ->multipleSelect('security_service_type_id', [$this, 'types'])
            ->multipleSelect('Classification', [$this, 'getTagsList'], [
                'fieldData' => 'Classifications.title',
            ])
            ->userField('ServiceOwner', 'ServiceOwners')
            ->userField('Collaborator', 'Collaborators')
            ->number('opex')
            ->number('capex')
            ->number('resource_utilization')
            ->userField('AuditOwner', 'AuditOwners')
            ->userField('AuditEvidenceOwner', 'AuditEvidenceOwners')
            ->text('audit_metric_description')
            ->text('audit_success_criteria')
            ->userField('MaintenanceOwner', 'MaintenanceOwners')
            ->text('maintenance_metric_description')
            ->multipleSelect('SecurityServiceIssue', [$this->SecurityServiceIssues, 'getList'], [
                'fieldData' => 'SecurityServiceIssues',
            ])
            ->multipleSelect('ServiceContract', [$this->ServiceContracts, 'getList'], [
                'fieldData' => 'ServiceContracts',
            ])
            ->multipleSelect('SecurityPolicy', [$this->SecurityPolicies, 'getList'], [
                'fieldData' => 'SecurityPolicies',
            ])
            ->multipleSelect('Project', [$this->Projects, 'getList'], [
                'fieldData' => 'Projects',
            ])
            ->multipleSelect('Risk', [$this->Risks, 'getList'], [
                'fieldData' => 'Risks',
            ])
            ->multipleSelect('ThirdPartyRisk', [$this->ThirdPartyRisks, 'getList'], [
                'fieldData' => 'ThirdPartyRisks',
            ])
            ->multipleSelect('BusinessContinuity', [$this->BusinessContinuities, 'getList'], [
                'fieldData' => 'BusinessContinuities',
            ])
            ->multipleSelect('SecurityIncident', [$this->SecurityIncidents, 'getList'], [
                'fieldData' => 'SecurityIncidents',
            ])
            ->multipleSelect('DataAsset', [$this->DataAssets, 'getList'], [
                'fieldData' => 'DataAssets',
            ])
            ->date('created')
            ->date('edited');

        $auditsTable = $this->getAssociation('SecurityServiceAudits')->getTarget();
        $auditStatuses = $auditsTable->getBehavior('DynamicStatus')->getDynamicStatuses();

        foreach ($auditStatuses as $status) {
            $name = 'audits_proportion_current_year_DynamicStatus_' . $status->get('id');
            $config
                ->number('{{' . $name . '}}', [
                    'macro' => new DynamicStatusIntegerMacro(
                        $name,
                        __('Child Audits Percentile Current Calendar Year Status = {0}', [$status->get('name')]),
                        ['year' => date('Y'), 'status' => $status],
                        [$this, 'statusAuditsStatusProportion']
                    ),
                    'trigger' => DynamicStatusesTable::TRIGGER_DATE,
                    'dependent' => DynamicStatusesTable::DEPENDENT,
                ]);

            $name = 'audits_proportion_previous_year_DynamicStatus_' . $status->get('id');
            $config
                ->number('{{' . $name . '}}', [
                    'macro' => new DynamicStatusIntegerMacro(
                        $name,
                        __('Child Audits Percentile Last Calendar Year Status = {0}', [$status->get('name')]),
                        ['year' => date('Y', strtotime('-1 year')), 'status' => $status],
                        [$this, 'statusAuditsStatusProportion']
                    ),
                    'trigger' => DynamicStatusesTable::TRIGGER_DATE,
                    'dependent' => DynamicStatusesTable::DEPENDENT,
                ]);
        }

        $config
            // functions
            ->group('function', __('Functions'))
            ->number('{{audits_count}}', [
                'macro' => new DynamicStatusIntegerMacro(
                    'audits_count',
                    __('Child Audits Count'),
                    [],
                    [$this, 'auditsCountMacro']
                ),
            ])
            ->number('{{audits_count_current_year}}', [
                'macro' => new DynamicStatusIntegerMacro(
                    'audits_count_current_year',
                    __('Child Audits Count Current Calendar Year'),
                    ['year' => date('Y')],
                    [$this, 'auditsCountMacro']
                ),
            ])
            ->number('{{audits_count_previous_year}}', [
                'macro' => new DynamicStatusIntegerMacro(
                    'audits_count_previous_year',
                    __('Child Audits Count Last Calendar Year'),
                    ['year' => date('Y', strtotime('-1 year'))],
                    [$this, 'auditsCountMacro']
                ),
            ])
            ->relatedCounts('ServiceContracts')
            ->relatedCounts('SecurityPolicies')
            ->relatedCounts('SecurityServiceIssues')
            ->relatedCounts('Risks')
            ->relatedCounts('ThirdPartyRisks')
            ->relatedCounts('BusinessContinuities')
            ->relatedCounts('SecurityIncidents')
            ->relatedCounts('DataAssets')
            ->relatedCounts('Projects')
            ->relatedCounts('ComplianceManagements');

        $config
            // related statuses
            ->group('related-statuses', __('Related Statuses'))
            ->relatedStatuses('ServiceContracts')
            ->relatedStatuses('SecurityPolicies')
            ->relatedStatuses('SecurityServiceAudits')
            ->relatedStatuses('SecurityServiceMaintenances')
            ->relatedStatuses('SecurityServiceIssues')
            ->relatedStatuses('Risks')
            ->relatedStatuses('ThirdPartyRisks')
            ->relatedStatuses('BusinessContinuities')
            ->relatedStatuses('SecurityIncidents')
            ->relatedStatuses('DataAssets')
            ->relatedStatuses('Projects');
    }

    public function statusAuditsStatusProportion($id, $params): int
    {
        $auditsTable = $this->getAssociation('SecurityServiceAudits')->getTarget();

        $status = $params['status'];
        $proportion = 0;

        $query = $auditsTable
            ->find(
                'list',
                keyField: 'id',
                valueField: 'id'
            )
            ->where([
                $auditsTable->aliasField('security_service_id') => $id,
            ]);

        if (isset($params['year'])) {
            $query
                ->where([
                    'YEAR(' . $auditsTable->aliasField('planned_date') . ')' => $params['year'],
                ]);
        }

        $ids = $query->toArray();

        if ($ids) {
            $dynamicStatusValuesTable = FactoryLocator::get('Table')->get('DynamicStatus.DynamicStatusValues');
            $statusCount = $dynamicStatusValuesTable
                ->find()
                ->where([
                    'DynamicStatusValues.model' => $auditsTable->getRegistryAlias(),
                    'DynamicStatusValues.foreign_key IN' => $ids,
                    'DynamicStatusValues.dynamic_status_id' => $status->get('id'),
                    'DynamicStatusValues.value' => 1,
                ])
                ->count();

            $proportion = (int)($statusCount / count($ids) * 100);
        }

        return $proportion;
    }

    public function auditsCountMacro($id, $params)
    {
        $query = $this->SecurityServiceAudits->find()
            ->where([
                'SecurityServiceAudits.security_Service_id' => $id,
            ]);

        if (isset($params['year'])) {
            $query->where([
                'YEAR(SecurityServiceAudits.planned_date)' => $params['year'],
            ]);
        }

        return $query->count();
    }

    public function getListNoDesign()
    {
        return $this->find('list')
            ->where([
                'SecurityServices.security_service_type_id !=' => self::TYPE_DESIGN,
            ])
            ->toArray();
    }

    public function buildReportsConfig(EventInterface $event, ArrayObject $config): void
    {
        $config['table']['model'] = ['SecurityServiceAudits', 'SecurityServiceMaintenances'];

        $config['table']['fields'] = array_merge($config['table']['fields'], [
            'id',
            'name',
            'objective',
            'documentation_url',
            'opex',
            'capex',
            'resource_utilization',
            'audit_metric_description',
            'audit_success_criteria',
            'maintenance_metric_description',
            'security_service_type_id',
            'Classification' => 'Classifications',
            'ServiceOwner' => 'ServiceOwners',
            'Collaborator' => 'Collaborators',
            'ServiceContract' => 'ServiceContracts',
            'SecurityPolicy' => 'SecurityPolicies',
            'AuditOwner' => 'AuditOwners',
            'AuditEvidenceOwner' => 'AuditEvidenceOwners',
            'MaintenanceOwner' => 'MaintenanceOwners',
            'SecurityServiceAudit' => 'SecurityServiceAudits',
            'SecurityServiceMaintenance' => 'SecurityServiceMaintenances',
            'Project' => 'Projects',
            'edited',
        ]);

        $auditResultsChart = [
            'title' => __('Audits by Result'),
            'description' => __('This chart shows the count of pass, failed and expired audits.'),
            'type' => ReportBlockChartSettingsTable::TYPE_PIE,
            'className' => 'AuditResultsChart',
            'params' => [],
            'finder' => [
                'contain' => [
                    'SecurityServiceAudits' => [
                        'fields' => [
                            'id', 'security_service_id', 'planned_date', 'security_service_audit_result_option_id',
                        ],
                    ],
                ],
            ],
        ];
        $config['chart'][1] = $auditResultsChart + [
                'templateType' => ReportTemplatesTable::TYPE_ITEM,
            ];
        $config['chart'][2] = $auditResultsChart + [
                'templateType' => ReportTemplatesTable::TYPE_SECTION,
                'visualisations' => true,
            ];

        $controlsByMitigationChart = [
            'title' => __('Controls by Mitigation'),
            'description' => __('This ven diagram shows the proportion on how controls are used against Asset Risks, Third Party Risks, Business Risks, Compliance and Data Flow Analysis.'),
            'type' => ReportBlockChartSettingsTable::TYPE_PIE,
            'className' => 'RelatedObjectsCountChart',
            'params' => [
                'assoc' => [
                    'Risks',
                    'ThirdPartyRisks',
                    'BusinessContinuities',
                    'ComplianceManagements',
                    'DataAssets',
                ],
            ],
            'finder' => [
                'contain' => [
                    'Risks' => [
                        'fields' => ['id'],
                    ],
                    'ThirdPartyRisks' => [
                        'fields' => ['id'],
                    ],
                    'BusinessContinuities' => [
                        'fields' => ['id'],
                    ],
                    'ComplianceManagements' => [
                        'fields' => ['id'],
                    ],
                    'DataAssets' => [
                        'fields' => ['id'],
                    ],
                ],
            ],
        ];
        $config['chart'][3] = $controlsByMitigationChart + [
                'templateType' => ReportTemplatesTable::TYPE_ITEM,
            ];
        $config['chart'][4] = $controlsByMitigationChart + [
                'templateType' => ReportTemplatesTable::TYPE_SECTION,
                'visualisations' => true,
            ];

        $auditResultsOverTimeChart = [
            'title' => __('Audits Results Over Time'),
            'description' => __('This chart shows all audit records over time which ones failed, pass, are missing or are scheduled in the future.'),
            'type' => ReportBlockChartSettingsTable::TYPE_BAR,
            'className' => 'AuditResultTimelineChart',
            'params' => [],
            'finder' => [
                'contain' => [
                    'SecurityServiceAudits' => [
                        'fields' => [
                            'id', 'security_service_id', 'security_service_audit_result_option_id', 'planned_date',
                        ],
                    ],
                ],
            ],
        ];
        $config['chart'][5] = $auditResultsOverTimeChart + [
                'templateType' => ReportTemplatesTable::TYPE_ITEM,
            ];
        $config['chart'][6] = $auditResultsOverTimeChart + [
                'templateType' => ReportTemplatesTable::TYPE_SECTION,
                'visualisations' => true,
            ];

        $config['chart'][7] = [
            'title' => __('Related Compliance Items'),
            'description' => __('This tree chart shows all related compliance requirements linked to this item.'),
            'type' => ReportBlockChartSettingsTable::TYPE_TREE,
            'templateType' => ReportTemplatesTable::TYPE_ITEM,
            'className' => 'RelatedComplianceItemsChart',
            'params' => [],
            'finder' => [
                'contain' => [
                    'ComplianceManagements' => [
                        'fields' => ['id'],
                        'CompliancePackageItems' => [
                            'fields' => ['id', 'item_id', 'name'],
                            'CompliancePackages' => [
                                'fields' => ['id'],
                                'CompliancePackageRegulators' => [
                                    'fields' => ['id', 'name'],
                                ],
                            ],
                        ],
                    ],
                ],
            ],
        ];

        $config['chart'][8] = [
            'title' => __('Related Risk Items'),
            'description' => __('This tree chart shows all related risk items linked.'),
            'type' => ReportBlockChartSettingsTable::TYPE_TREE,
            'templateType' => ReportTemplatesTable::TYPE_ITEM,
            'className' => 'RelatedObjectsChart',
            'params' => [
                'assoc' => [
                    'Risks', 'ThirdPartyRisks', 'BusinessContinuities',
                ],
            ],
            'finder' => [
                'contain' => [
                    'Risks' => [
                        'fields' => ['id', 'title'],
                    ],
                    'ThirdPartyRisks' => [
                        'fields' => ['id', 'title'],
                    ],
                    'BusinessContinuities' => [
                        'fields' => ['id', 'title'],
                    ],
                ],
            ],
        ];

        $config['chart'][9] = [
            'title' => __('Related Policy Items'),
            'description' => __('This tree chart shows all related policies linked to this item.'),
            'type' => ReportBlockChartSettingsTable::TYPE_TREE,
            'templateType' => ReportTemplatesTable::TYPE_ITEM,
            'className' => 'RelatedObjectsChart',
            'params' => [
                'assoc' => [
                    'SecurityPolicies',
                ],
            ],
            'finder' => [
                'contain' => [
                    'SecurityPolicies' => [
                        'fields' => ['id', 'index'],
                    ],
                ],
            ],
        ];

        $config['chart'][9] = [
            'title' => __('Related Policy Items'),
            'description' => __('This tree chart shows all related policies linked to this item.'),
            'type' => ReportBlockChartSettingsTable::TYPE_TREE,
            'templateType' => ReportTemplatesTable::TYPE_ITEM,
            'className' => 'RelatedObjectsChart',
            'params' => [
                'assoc' => [
                    'SecurityPolicies',
                ],
            ],
            'finder' => [
                'contain' => [
                    'SecurityPolicies' => [
                        'fields' => ['id', 'index'],
                    ],
                ],
            ],
        ];

        $config['chart'][10] = [
            'title' => __('Top 10 Fail Controls by Testing (by proportion)'),
            'description' => __('This chart shows the top ten controls for the last calendar year that failed the largest proportion of audits.'),
            'type' => ReportBlockChartSettingsTable::TYPE_BAR,
            'templateType' => ReportTemplatesTable::TYPE_SECTION,
            'visualisations' => true,
            'className' => 'FailedAuditsChart',
            'params' => [
                'percentage' => true,
                'year' => date('Y'),
            ],
            'finder' => [
                'contain' => [
                    'SecurityServiceAudits' => [
                        'fields' => [
                            'id', 'security_service_id', 'planned_date', 'security_service_audit_result_option_id',
                        ],
                    ],
                ],
            ],
        ];

        $config['chart'][11] = [
            'title' => __('Top 10 Fail Controls by Testing (by counter)'),
            'description' => __('This chart shows the top ten controls for the last calendar year based on the total number of failed audits. A second bar shows the total number of audits for the last calendar year.'),
            'type' => ReportBlockChartSettingsTable::TYPE_BAR,
            'templateType' => ReportTemplatesTable::TYPE_SECTION,
            'visualisations' => true,
            'className' => 'FailedAuditsChart',
            'params' => [
                'year' => date('Y'),
            ],
            'finder' => [
                'contain' => [
                    'SecurityServiceAudits' => [
                        'fields' => [
                            'id', 'security_service_id', 'planned_date', 'security_service_audit_result_option_id',
                        ],
                    ],
                ],
            ],
        ];

        $auditResultsCurrentYearChart = [
            'title' => __('Audits by Result (current calendar year)'),
            'description' => __('This chart shows the proportion of pass, failed and expired audits for this current year.'),//phpcs:ignore
            'type' => ReportBlockChartSettingsTable::TYPE_PIE,
            'className' => 'AuditResultsChart',
            'params' => [
                'percentage' => true,
                'year' => date('Y'),
            ],
            'finder' => [
                'contain' => [
                    'SecurityServiceAudits' => [
                        'fields' => [
                            'id', 'planned_date', 'security_service_audit_result_option_id', 'security_service_id',
                        ],
                    ],
                ],
            ],
        ];
        $config['chart'][12] = $auditResultsCurrentYearChart + [
                'templateType' => ReportTemplatesTable::TYPE_ITEM,
            ];
        $config['chart'][13] = $auditResultsCurrentYearChart + [
                'templateType' => ReportTemplatesTable::TYPE_SECTION,
                'visualisations' => true,
            ];

        $auditResultsPastYearChart = [
            'title' => __('Audits by Result (past calendar year)'),
            'description' => __('This chart shows the proportion of pass, failed and expired audits for past year.'),
            'type' => ReportBlockChartSettingsTable::TYPE_PIE,
            'className' => 'AuditResultsChart',
            'params' => [
                'percentage' => true,
                'year' => date('Y', strtotime('-1 year')),
            ],
            'finder' => [
                'contain' => [
                    'SecurityServiceAudits' => [
                        'fields' => [
                            'id', 'security_service_id', 'planned_date', 'security_service_audit_result_option_id',
                        ],
                    ],
                ],
            ],
        ];
        $config['chart'][14] = $auditResultsPastYearChart + [
                'templateType' => ReportTemplatesTable::TYPE_ITEM,
            ];
        $config['chart'][15] = $auditResultsPastYearChart + [
                'templateType' => ReportTemplatesTable::TYPE_SECTION,
                'visualisations' => true,
            ];

        $config['chart']['crud-actions-section'] = [
            'title' => __('Crud Actions'),
            'description' => __(''),
            'type' => ReportBlockChartSettingsTable::TYPE_BAR,
            'templateType' => ReportTemplatesTable::TYPE_SECTION,
            'visualisations' => true,
            'className' => 'CrudActionsChart',
            'params' => [],
            'finder' => [
                'contain' => [],
            ],
        ];

        $config['chart'] = $config['chart'] + DashboardManager::dashboardCharts();
    }

    public function buildNotificationSystemConfig(EventInterface $event, ArrayObject $notifications, ArrayObject $options): void
    {
        $options->offsetSet('macros', true);

        $notifications->offsetSet('object_reminder', [
            'type' => NotificationSystemItemsTable::TYPE_AWARENESS,
            'className' => '.ObjectReminder',
            'label' => __('Recurrent Awareness Reminder'),
        ]);

        /** @var \App\Model\Table\FiltersTable $filtersTable */
        $filtersTable = $this->fetchTable('Filters');
        $expiredFilter = $filtersTable->find()
            ->where([
                'slug' => 'missing-audits',
                'model' => 'SecurityServices',
            ])
            ->first();

        if ($expiredFilter) {
            $options['seed']['filer-missing-audits'] = [
                'name' => __('Internal Controls with Expired Audits'),
                'slug' => 'filer-missing-audits',
                'notification' => 'advanced_filters',
                'notification_users' => [
                    'Group-10',
                ],
                'filter_id' => $expiredFilter->get('id'),
                'report_attachment_type' => NotificationSystemItemsTable::REPORT_ATTACHEMENT_PDF,
                'report_send_empty_results' => 1,
                'trigger_period' => 6,
                'email_subject' => __('Internal Controls with Expired Audits'),
                'email_body' => nl2br(__('Hello,

This is a weekly report with all expired Internal Controls.

Click on the link below to access the module:

%SECTION_URL%

Thank you')),
            ];
        }

        $this->seedNotification('created', [
            'notification_system_item_custom_roles' => [
                'SecurityServices.ServiceOwners',
                'SecurityServices.Collaborators',
            ],
        ]);
        $this->seedNotification('edited', [
            'notification_system_item_custom_roles' => [
                'SecurityServices.ServiceOwners',
                'SecurityServices.Collaborators',
            ],
        ]);
        $this->seedNotification('deleted', [
            'notification_system_item_custom_roles' => [
                'SecurityServices.ServiceOwners',
                'SecurityServices.Collaborators',
            ],
        ]);
        $this->seedNotification('widget_object', [
            'notification_system_item_custom_roles' => [
                'SecurityServices.ServiceOwners',
                'SecurityServices.Collaborators',
            ],
        ]);
    }

    public function buildImportToolConfig(EventInterface $event, ArrayObject $config): void
    {
        $collection = $this->getBehavior('FieldData')->getCollection();

        $config['name'] = [
            'name' => $collection->get('name')->getLabel(),
            'headerTooltip' => __('This field is mandatory.'),
        ];
        $config['objective'] = [
            'name' => $collection->get('objective')->getLabel(),
            'headerTooltip' => __('This field is optional.'),
        ];
        $config['documentation_url'] = [
            'name' => $collection->get('documentation_url')->getLabel(),
            'headerTooltip' => __('Optional, you can leave this field blank.'),
        ];
        $config['security_service_type_id'] = [
            'name' => $collection->get('security_service_type_id')->getLabel(),
            'headerTooltip' => __(
                'Mandatory, can be one of the following numbers: {0}',
                ImportTool::formatList(self::types())
            ),
        ];
        $config['Projects'] = [
            'name' => $collection->get('Projects')->getLabel(),
            'headerTooltip' => __('Optional and accepts multiple names separated by "|". You need to enter the name of a project, you can find them at Security Operations / Project Management.'),
            'association' => 'Projects',
            'objectAutoFind' => true,
        ];
        $config['classifications'] = [
            'name' => $collection->get('Classifications')->getLabel(),
            'headerTooltip' => __('Optional and accepts tags separated by "|". For example "Critical|Approved".'),
            'multiple' => true,
        ];
        $config['ServiceOwners'] = UserFields::getImportArgsFieldData('ServiceOwners', [
            'name' => $collection->get('ServiceOwners')->getLabel(),
        ]);
        $config['Collaborators'] = UserFields::getImportArgsFieldData('Collaborators', [
            'name' => $collection->get('Collaborators')->getLabel(),
        ]);
        $config['opex'] = [
            'name' => $collection->get('opex')->getLabel(),
            'headerTooltip' => __('Optional, leave it empty or insert a numerical value.'),
        ];
        $config['capex'] = [
            'name' => $collection->get('capex')->getLabel(),
            'headerTooltip' => __('Optional, leave it empty or insert a numerical value.'),
        ];
        $config['resource_utilization'] = [
            'name' => $collection->get('resource_utilization')->getLabel(),
            'headerTooltip' => __('Optional, leave it empty or insert a numerical value.'),
        ];
        $config['SecurityPolicies'] = [
            'name' => $collection->get('SecurityPolicies')->getLabel(),
            'headerTooltip' => __('Optional, accepts multiple names separated by "|". You can get the name of a policy from Control Catalogue / Policy Management.'),// phpcs:ignore
            'association' => 'SecurityPolicies',
            'objectAutoFind' => true,
        ];
        $config['AuditOwners'] = UserFields::getImportArgsFieldData('AuditOwners', [
            'name' => $collection->get('AuditOwners')->getLabel(),
            'headerTooltip' => __('Mandatory in case you set audit dates. Accepts multiple user logins or group names separated by "|". For User login use prefix "User-" and for Group name use "Group-". For example "User-admin|Group-Third Party Feedback|Group-Admin". You can get the login of an user account from System / Settings / User Management or name of a group from System / Settings / Groups.'),// phpcs:ignore
        ], false);
        $config['AuditEvidenceOwners'] = UserFields::getImportArgsFieldData('AuditEvidenceOwners', [
            'name' => $collection->get('AuditEvidenceOwners')->getLabel(),
            'headerTooltip' => __('Mandatory in case you set audit dates. Accepts multiple user logins or group names separated by "|". For User login use prefix "User-" and for Group name use "Group-". For example "User-admin|Group-Third Party Feedback|Group-Admin". You can get the login of an user account from System / Settings / User Management or name of a group from System / Settings / Groups.'),// phpcs:ignore
        ], false);
        $config['audit_metric_description'] = [
            'name' => $collection->get('audit_metric_description')->getLabel(),
            'headerTooltip' => __('Mandatory in case you set audit dates, you need to insert some text or NA if you are not interested in this feature.'),// phpcs:ignore
        ];
        $config['audit_success_criteria'] = [
            'name' => $collection->get('audit_success_criteria')->getLabel(),
            'headerTooltip' => __('Mandatory in case you set audit dates, you need to insert some text or NA if you are not interested in this feature.'),// phpcs:ignore
        ];
        $config['security_service_audit_dates_import'] = [
            'name' => __('Audit Date'),
            'headerTooltip' => __('Optional, you can insert date with the format DD-MM, bare in mind the delimiter is a "-", Accepts multiple values separated by "|". For example "22-01|15-10".'),// phpcs:ignore
            'multiple' => true,
        ];
        $config['MaintenanceOwners'] = UserFields::getImportArgsFieldData('MaintenanceOwners', [
            'name' => $collection->get('MaintenanceOwners')->getLabel(),
            'headerTooltip' => __('Mandatory in case you set maintenance dates. Accepts multiple user logins or group names separated by "|". For User login use prefix "User-" and for Group name use "Group-". For example "User-admin|Group-Third Party Feedback|Group-Admin". You can get the login of an user account from System / Settings / User Management or name of a group from System / Settings / Groups.'),// phpcs:ignore
        ], false);
        $config['maintenance_metric_description'] = [
            'name' => $collection->get('maintenance_metric_description')->getLabel(),
            'headerTooltip' => __('Mandatory in case you set maintenance dates, you can set NA if you wont want to use this feature.'),// phpcs:ignore
        ];
        $config['security_service_maintenance_dates_import'] = [
            'name' => __('Maintenance Date'),
            'headerTooltip' => __('Optional, you can insert date with the format DD-MM, bare in mind the delimiter is a "-", Accepts multiple values separated by "|". For example "22-01|15-10".'),// phpcs:ignore
            'multiple' => true,
        ];
    }

    public function getMacrosConfig(): array
    {
        return [
            'prefix' => 'internal_control',
            'seed' => [
                [$this, 'customMacros'],
            ],
        ];
    }

    public function customMacros(MacroCollection $collection): void
    {
        $subject = new stdClass();
        $subject->finder = [
            'contain' => [
                'ComplianceManagements' => [
                    'fields' => ['id'],
                    'CompliancePackageItems' => [
                        'fields' => ['id', 'item_id', 'name'],
                        'CompliancePackages' => [
                            'fields' => ['id'],
                            'CompliancePackageRegulators' => [
                                'fields' => ['id', 'name'],
                            ],
                        ],
                    ],
                ],
            ],
        ];
        $macro = new Macro($this->getMacroAlias('compliance_items_list'), __('List of Related Compliance Items'), $subject, function ($data, $subject) {
            $content = '';
            if ($data) {
                $helper = new SecurityServicesHelper(new View());
                $content = $helper->complianceItemsList($data);
            }

            return $content;
        });
        $collection->add($macro);

        $subject = new stdClass();
        $subject->finder = [
            'contain' => [
                'Risks' => [
                    'fields' => ['id', 'title'],
                ],
                'ThirdPartyRisks' => [
                    'fields' => ['id', 'title'],
                ],
                'BusinessContinuities' => [
                    'fields' => ['id', 'title'],
                ],
            ],
        ];
        $macro = new Macro($this->getMacroAlias('risk_items_list'), __('List of Related Risk Items'), $subject, function ($data, $subject) {
            $content = '';
            if ($data) {
                $helper = new SecurityServicesHelper(new View());
                $content = $helper->riskItemsList($data);
            }

            return $content;
        });
        $collection->add($macro);

        $subject = new stdClass();
        $subject->finder = [
            'contain' => [
                'DataAssets' => [
                    'fields' => ['id', 'data_asset_instance_id', 'data_asset_status_id', 'title'],
                    'DataAssetInstances' => [
                        'fields' => ['id', 'asset_id'],
                        'Assets' => [
                            'fields' => ['id', 'name'],
                        ],
                    ],
                ],
            ],
        ];
        $macro = new Macro($this->getMacroAlias('data_flow_items_list'), __('List of Related Data Flow Items'), $subject, function ($data, $subject) {
            $content = '';
            if ($data) {
                $helper = new SecurityServicesHelper(new View());
                $content = $helper->dataAssetItemsList($data);
            }

            return $content;
        });
        $collection->add($macro);
    }

    public function buildSectionInfoConfig(EventInterface $event, ArrayObject $config): void
    {
        $config['map'] = [
            'Risks',
            'ThirdPartyRisks',
            'BusinessContinuities',
            'SecurityServiceAudits' => [
                'mandatory' => false,
            ],
            'SecurityServiceIssues',
            'SecurityServiceMaintenances' => [
                'mandatory' => false,
            ],
            'Projects' => [
                'children' => [
                    'ProjectAchievements' => [
                        'mandatory' => false,
                    ],
                ],
            ],
            'SecurityPolicies',
            'ComplianceManagements',
        ];
    }

    public function findAdvancedFilter(EventInterface $event, Query $query)
    {
        $query
            ->contain([
                'SecurityServiceAudits',
                'SecurityServiceMaintenances',
                'SecurityServiceAuditDates',
                'SecurityServiceMaintenanceDates',
                'SecurityServiceIssues',
                'Classifications',
                'SecurityPolicies',
                'Risks',
                'ThirdPartyRisks',
                'BusinessContinuities',
                'SecurityIncidents',
                'ServiceContracts',
                'DataAssets' => [
                    'DataAssetInstances' => [
                        'Assets',
                    ],
                ],
                'Projects' => [
                    'ProjectAchievements',
                ],
                'ComplianceManagements' => [
                    'CompliancePackageItems' => [
                        'CompliancePackages' => [
                            'CompliancePackageRegulators',
                        ],
                    ],
                ],
            ]);

        $this->containUserField($query, 'ServiceOwners');
        $this->containUserField($query, 'Collaborators');
        $this->containUserField($query, 'AuditOwners');
        $this->containUserField($query, 'AuditEvidenceOwners');
        $this->containUserField($query, 'MaintenanceOwners');

        return $query;
    }

    /**
     * Form finder.
     *
     * @param \Cake\ORM\Query $query Query.
     * @return \Cake\ORM\Query
     */
    public function findForm(Query $query)
    {
        $query
            ->contain([
                'Classifications',
                'ServiceContracts',
                'SecurityPolicies',
                'Projects',
                'SecurityServiceAuditDates',
                'SecurityServiceMaintenanceDates',
            ]);

        return $query;
    }

    public function beforeMarshal(EventInterface $event, ArrayObject $data, ArrayObject $options)
    {
        if (isset($options['import']) && $options['import']) {
            $data['audit_calendar_type'] = YearlyCalendarBehavior::CALENDAR_TYPE_NO_DATES;

            if (
                isset($data['security_service_audit_dates_import'])
                && $data['security_service_audit_dates_import']
            ) {
                $data['audit_calendar_type'] = YearlyCalendarBehavior::CALENDAR_TYPE_SPECIFIC_DATES;

                $data['security_service_audit_dates'] = [];
                foreach ($data['security_service_audit_dates_import'] as $date) {
                    $parts = explode('-', $date);
                    if (count($parts) == 2) {
                        $data['security_service_audit_dates'][] = [
                            'day' => $parts[0],
                            'month' => $parts[1],
                        ];
                    }
                }
            }

            $data['maintenance_calendar_type'] = YearlyCalendarBehavior::CALENDAR_TYPE_NO_DATES;

            if (
                isset($data['security_service_maintenance_dates_import'])
                && $data['security_service_maintenance_dates_import']
            ) {
                $data['maintenance_calendar_type'] = YearlyCalendarBehavior::CALENDAR_TYPE_SPECIFIC_DATES;

                $data['security_service_maintenance_dates'] = [];
                foreach ($data['security_service_maintenance_dates_import'] as $date) {
                    $parts = explode('-', $date);
                    if (count($parts) == 2) {
                        $data['security_service_maintenance_dates'][] = [
                            'day' => $parts[0],
                            'month' => $parts[1],
                        ];
                    }
                }
            }
        }
    }

    /**
     * BeforeSave handles re-save of all incomplete and future audits and maintenances with the curent entity data.
     *
     * @param \Cake\Event\EventInterface $event Event.
     * @param \Cake\Datasource\EntityInterface $entity Entity.
     * @param \ArrayObject $option Options.
     */
    public function beforeSave(EventInterface $event, EntityInterface $entity, ArrayObject $options)
    {
        // when editing a control we delegate modified value of audit and maintenance criterias and methodology fields to
        // the control's incomplete audits and maintenances
        if ($entity->isNew() === false) {
            if ($entity->isDirty()) {
                $conds = $entity->get('audit_calendar_type') !== YearlyCalendarBehavior::CALENDAR_TYPE_NO_DATES;
                $conds &= $entity->get('security_service_audit_dates') !== null;
                if ($conds) {
                    $auditsTable = $this->getAssociation('SecurityServiceAudits');
                    $q = $auditsTable
                        ->find('incomplete')
                        ->find('future')
                        ->contain([
                            'AuditOwners',
                            'AuditEvidenceOwners',
                        ])
                        ->where([
                            'SecurityServiceAudits.security_service_id' => $entity->get('id'),
                        ]);

                    $or = [];
                    foreach ($entity->get('security_service_audit_dates') as $date) {
                        $format = date('m-d', (int)strtotime('2021-' . $date->get('month') . '-' . $date->get('day')));

                        $or[] = [
                            'SecurityServiceAudits.planned_date LIKE' => '%-' . $format,
                        ];
                    }

                    $q->where([
                        'OR' => $or,
                    ]);

                    $data = $q->toArray();
                    $ids = (array)Hash::extract($data, '{n}.id');

                    $parseOwnerUsers = UserFieldsBehavior::codeFromEntity(
                        $entity,
                        'user_field__audit_owners__users',
                        UserFieldsBehavior::ASSOC_TYPE_USER
                    );

                    $parseOwnerGroups = UserFieldsBehavior::codeFromEntity(
                        $entity,
                        'user_field__audit_owners__groups',
                        UserFieldsBehavior::ASSOC_TYPE_GROUP
                    );

                    $auditOwners = array_merge($parseOwnerUsers, $parseOwnerGroups);

                    $parseEvidenceOwnerUsers = UserFieldsBehavior::codeFromEntity(
                        $entity,
                        'user_field__audit_evidence_owners__users',
                        UserFieldsBehavior::ASSOC_TYPE_USER
                    );

                    $parseEvidenceOwnerGroups = UserFieldsBehavior::codeFromEntity(
                        $entity,
                        'user_field__audit_evidence_owners__groups',
                        UserFieldsBehavior::ASSOC_TYPE_GROUP
                    );

                    $auditEvidenceOwners = array_merge($parseEvidenceOwnerUsers, $parseEvidenceOwnerGroups);

                    $audits = [];
                    foreach ($ids as $id) {
                        $patchAudit = [
                            'id' => $id,
                        ];

                        $patchAudit['audit_metric_description'] = $entity->get('audit_metric_description');
                        $patchAudit['audit_success_criteria'] = $entity->get('audit_success_criteria');
                        $patchAudit['audit_owners'] = $auditOwners;
                        $patchAudit['audit_evidence_owners'] = $auditEvidenceOwners;

                        $audits[] = $patchAudit;
                    }

                    $this->patchEntity($entity, [
                        'security_service_audits' => $audits,
                    ], [
                        'associated' => [
                            'SecurityServiceAudits' => ['accessibleFields' => ['*' => true]],
                            'SecurityServiceAudits.UserField_AuditOwners_Users',
                            'SecurityServiceAudits.UserField_AuditOwners_Groups',
                            'SecurityServiceAudits.UserField_AuditEvidenceOwners_Users',
                            'SecurityServiceAudits.UserField_AuditEvidenceOwners_Groups',
                        ],
                    ]);
                }

                $conds = $entity->get('maintenance_calendar_type') !== YearlyCalendarBehavior::CALENDAR_TYPE_NO_DATES;
                $conds &= $entity->get('security_service_maintenance_dates') !== null;
                if ($conds) {
                    $maintenancesTable = $this->getAssociation('SecurityServiceMaintenances');
                    $q = $maintenancesTable
                        ->find('incomplete')
                        ->find('future')
                        ->contain([
                            'MaintenanceOwners',
                        ])
                        ->where([
                            'SecurityServiceMaintenances.security_service_id' => $entity->get('id'),
                        ]);

                    $or = [];
                    foreach ($entity->get('security_service_maintenance_dates') as $date) {
                        $format = date('m-d', (int)strtotime('2021-' . $date->get('month') . '-' . $date->get('day')));

                        $or[] = [
                            'SecurityServiceMaintenances.planned_date LIKE' => '%-' . $format,
                        ];
                    }

                    $q->where([
                        'OR' => $or,
                    ]);

                    $data = $q->toArray();
                    $ids = (array)Hash::extract($data, '{n}.id');

                    $parseOwnerUsers = UserFieldsBehavior::codeFromEntity(
                        $entity,
                        'user_field__maintenance_owners__users',
                        UserFieldsBehavior::ASSOC_TYPE_USER
                    );

                    $parseOwnerGroups = UserFieldsBehavior::codeFromEntity(
                        $entity,
                        'user_field__maintenance_owners__groups',
                        UserFieldsBehavior::ASSOC_TYPE_GROUP
                    );

                    $maintenanceOwners = array_merge($parseOwnerUsers, $parseOwnerGroups);

                    $maintenances = [];
                    foreach ($ids as $id) {
                        $patchMaintenance = [
                            'id' => $id,
                            'task' => $entity->get('maintenance_metric_description'),
                        ];

                        $patchMaintenance['maintenance_owners'] = $maintenanceOwners;

                        $maintenances[] = $patchMaintenance;
                    }

                    $this->patchEntity($entity, [
                        'security_service_maintenances' => $maintenances,
                    ], [
                        'associated' => [
                            'SecurityServiceMaintenances' => ['accessibleFields' => ['*' => true]],
                            'SecurityServiceMaintenances.UserField_MaintenanceOwners_Users',
                            'SecurityServiceMaintenances.UserField_MaintenanceOwners_Groups',
                        ],
                    ]);
                }
            }
        }
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

        $properties = $apiBehavior->filterProperties($properties, [
            'id' => [
                'readOnly' => true,
                'minLength' => 0,
            ],
            'name' => [
                'minLength' => 0,
            ],
            'objective' => [
                'minLength' => 0,
            ],
            'security_service_type_id' => [
                'description' => ApiBehavior::optionsDescription(self::types()),
                'minLength' => 0,
                'enum' => [],
            ],
            'documentation_url' => [
                'minLength' => 0,
            ],
            'audit_calendar_type' => [
                'description' => ApiBehavior::optionsDescription(YearlyCalendarBehavior::types()),
                'minLength' => 0,
                'readOnly' => true,
            ],
            'audit_calendar_recurrence_start_date' => [
                'readOnly' => true,
                'minLength' => 0,
            ],
            'audit_calendar_recurrence_frequency' => [
                'readOnly' => true,
                'minLength' => 0,
            ],
            'audit_calendar_recurrence_period' => [
                'readOnly' => true,
                'minLength' => 0,
            ],
            'audit_metric_description' => [
                'minLength' => 0,
            ],
            'audit_success_criteria' => [
                'minLength' => 0,
            ],
            'maintenance_calendar_type' => [
                'description' => ApiBehavior::optionsDescription(YearlyCalendarBehavior::types()),
                'readOnly' => true,
                'minLength' => 0,
            ],
            'maintenance_calendar_recurrence_start_date' => [
                'readOnly' => true,
                'minLength' => 0,
            ],
            'maintenance_calendar_recurrence_frequency' => [
                'readOnly' => true,
                'minLength' => 0,
            ],
            'maintenance_calendar_recurrence_period' => [
                'readOnly' => true,
                'minLength' => 0,
            ],
            'maintenance_metric_description' => [
                'minLength' => 0,
            ],
            'opex' => [
                'minLength' => 0,
            ],
            'capex' => [
                'minLength' => 0,
            ],
            'resource_utilization' => [
                'minLength' => 0,
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

        $apiBehavior->addAssociationProperty($properties, 'Classifications', [
            'description' => __('Save as an array of tags ["tag1", "tag2", ...].')
        ]);

        $apiBehavior->addUserFieldProperty($properties, 'ServiceOwners');
        $apiBehavior->addUserFieldProperty($properties, 'Collaborators');
        $apiBehavior->addUserFieldProperty($properties, 'AuditOwners');
        $apiBehavior->addUserFieldProperty($properties, 'AuditEvidenceOwners');
        $apiBehavior->addUserFieldProperty($properties, 'MaintenanceOwners');

        $apiBehavior->addAssociationProperty($properties, 'SecurityServiceAuditDates', [
            'description' => __('Save as an array of dates in format [{"month" => "01", "day" => "30"}, {"month" => "05", "day" => "17"}, ...].')
        ]);
        $apiBehavior->addAssociationProperty($properties, 'SecurityServiceMaintenanceDates', [
            'description' => __('Save as an array of dates in format [{"month" => "01", "day" => "30"}, {"month" => "05", "day" => "17"}, ...].')
        ]);

        $apiBehavior->addAssociationProperty($properties, 'SecurityServiceAudits', [
            'readOnly' => true,
        ]);
        $apiBehavior->addAssociationProperty($properties, 'SecurityServiceMaintenances', [
            'readOnly' => true,
        ]);
        $apiBehavior->addAssociationProperty($properties, 'SecurityServiceIssues', [
            'readOnly' => true,
        ]);

        $apiBehavior->addAssociationProperty($properties, 'ServiceContracts');
        $apiBehavior->addAssociationProperty($properties, 'SecurityPolicies');
        $apiBehavior->addAssociationProperty($properties, 'Risks', [
            'readOnly' => true,
        ]);
        $apiBehavior->addAssociationProperty($properties, 'ThirdPartyRisks', [
            'readOnly' => true,
        ]);
        $apiBehavior->addAssociationProperty($properties, 'BusinessContinuities', [
            'readOnly' => true,
        ]);
        $apiBehavior->addAssociationProperty($properties, 'SecurityIncidents', [
            'readOnly' => true,
        ]);
        $apiBehavior->addAssociationProperty($properties, 'DataAssets', [
            'readOnly' => true,
        ]);
        $apiBehavior->addAssociationProperty($properties, 'ComplianceManagements', [
            'readOnly' => true,
        ]);
        $apiBehavior->addAssociationProperty($properties, 'Projects');

        $schema->setProperties($properties);
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

        $config['routes'][__('SecurityServices')] = [
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
            'name' => [
                'type' => 'string',
            ],
            'objective' => [
                'type' => 'string',
            ],
            'security_service_type_id' => [
                'type' => 'integer',
            ],
            'documentation_url' => [
                'type' => 'string',
            ],
            'audit_metric_description' => [
                'type' => 'string',
            ],
            'audit_success_criteria' => [
                'type' => 'string',
            ],
            'maintenance_metric_description' => [
                'type' => 'string',
            ],
            'opex' => [
                'type' => 'integer',
            ],
            'capex' => [
                'type' => 'integer',
            ],
            'resource_utilization' => [
                'type' => 'integer',
            ],
            'classifications' => [
                'type' => 'array',
                'description' => __('Save as an array of tags ["tag1", "tag2", ...].'),
            ],
            'security_service_audit_dates' => [
                'type' => 'array',
                'description' => __('Save as an array of dates in format [{"month" => "01", "day" => "30"}, {"month" => "05", "day" => "17"}, ...].'), // phpcs:ignore
            ],
            'security_service_maintenance_dates' => [
                'type' => 'array',
                'description' => __('Save as an array of dates in format [{"month" => "01", "day" => "30"}, {"month" => "05", "day" => "17"}, ...].'), // phpcs:ignore
            ],
            'service_contracts' => [
                'type' => 'array',
            ],
            'security_policies' => [
                'type' => 'array',
            ],
            'projects' => [
                'type' => 'array',
            ],
        ];

        $config['schema'] = array_merge($config['schema'], $schema);
    }

    /**
     * Base API finder.
     *
     * @param \Cake\ORM\Query $query Query.
     * @return \Cake\ORM\Query
     */
    public function findApiBase(Query $query)
    {
        return $query
            ->select([
                'SecurityServices.id', 'SecurityServices.name', 'SecurityServices.objective',
                'SecurityServices.security_service_type_id', 'SecurityServices.service_classification_id',
                'SecurityServices.documentation_url', 'SecurityServices.audit_calendar_type',
                'SecurityServices.audit_calendar_recurrence_start_date', 'SecurityServices.audit_calendar_recurrence_frequency',
                'SecurityServices.audit_calendar_recurrence_period', 'SecurityServices.audit_metric_description',
                'SecurityServices.audit_success_criteria', 'SecurityServices.maintenance_calendar_type',
                'SecurityServices.maintenance_calendar_recurrence_start_date', 'SecurityServices.maintenance_calendar_recurrence_frequency',
                'SecurityServices.maintenance_calendar_recurrence_period', 'SecurityServices.maintenance_metric_description',
                'SecurityServices.opex', 'SecurityServices.capex', 'SecurityServices.resource_utilization',
                'SecurityServices.created', 'SecurityServices.edited',
            ]);
    }

    /**
     * API finder.
     *
     * @param \Cake\ORM\Query $query Query.
     * @return \Cake\ORM\Query
     */
    public function findApi(Query $query)
    {
        return $query
            ->find('apiBase')
            ->contain([
                'ServiceOwners' => [
                    'finder' => 'apiBase',
                ],
                'Collaborators' => [
                    'finder' => 'apiBase',
                ],
                'AuditOwners' => [
                    'finder' => 'apiBase',
                ],
                'AuditEvidenceOwners' => [
                    'finder' => 'apiBase',
                ],
                'MaintenanceOwners' => [
                    'finder' => 'apiBase',
                ],
                'SecurityServiceAudits' => [
                    'finder' => 'apiBase',
                ],
                'SecurityServiceMaintenances' => [
                    'finder' => 'apiBase',
                ],
                'SecurityServiceIssues' => [
                    'finder' => 'apiBase',
                ],
                'SecurityServiceAuditDates' => [
                    'finder' => 'apiBase',
                ],
                'SecurityServiceMaintenanceDates' => [
                    'finder' => 'apiBase',
                ],
                'Classifications' => [
                    'finder' => 'apiBase',
                ],
                'ServiceContracts' => [
                    'finder' => 'apiBase',
                ],
                'SecurityPolicies' => [
                    'finder' => 'apiBase',
                ],
                'Risks' => [
                    'finder' => 'apiBase',
                ],
                'ThirdPartyRisks' => [
                    'finder' => 'apiBase',
                ],
                'BusinessContinuities' => [
                    'finder' => 'apiBase',
                ],
                'SecurityIncidents' => [
                    'finder' => 'apiBase',
                ],
                'DataAssets' => [
                    'finder' => 'apiBase',
                ],
                'ComplianceManagements' => [
                    'finder' => 'apiBase',
                ],
                'Projects' => [
                    'finder' => 'apiBase',
                ],
            ]);
    }

    public function recalculateAuditStatus(int $id)
    {
        $auditIds = $this->SecurityServiceAudits->find('list', [
            'valueField' => 'id',
        ])
            ->where([
                'SecurityServiceAudits.security_service_id' => $id,
            ])
            ->toArray();

        if ($auditIds) {
            $this->SecurityServiceAudits->triggerDynamicStatus($auditIds, [], [
                'triggerDependent' => false,
            ]);
        }

        $this->triggerDynamicStatus($id);
    }

    public function recalculateMaintenanceStatus(int $id)
    {
        $maintenanceIds = $this->SecurityServiceMaintenances->find('list', [
            'valueField' => 'id',
        ])
            ->where([
                'SecurityServiceMaintenances.security_service_id' => $id,
            ])
            ->toArray();

        if ($maintenanceIds) {
            $this->SecurityServiceMaintenances->triggerDynamicStatus($maintenanceIds, [], [
                'triggerDependent' => false,
            ]);
        }

        $this->triggerDynamicStatus($id);
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
            ->contain([
                'ServiceOwners',
                'Collaborators',
                'AuditOwners',
                'AuditEvidenceOwners',
                'MaintenanceOwners',
            ]);
    }
}
