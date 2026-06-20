package system.authz

default allow = false

allow if {
    input.user.role == "admin"
}

allow if {
    input.user.role == "employee"
    input.request.method == "GET"
    input.request.path == "/donnees-publiques"
}
