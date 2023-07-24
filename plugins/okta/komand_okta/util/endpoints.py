ADD_USER_TO_GROUP_ENDPOINT = "/api/v1/groups/{group_id}/users/{user_id}"
ASSIGN_USER_TO_APP_SSO_ENDPOINT = "/api/v1/apps/{app_id}/users"
DEACTIVATE_USER_ENDPOINT = "/api/v1/users/{user_id}/lifecycle/deactivate"
GET_FACTORS_ENDPOINT = "/api/v1/users/{user_id}/factors"
GET_USER_BY_LOGIN_ENDPOINT = "/api/v1/users/{login}"
GET_USER_GROUPS_ENDPOINT = "/api/v1/users/{user_id}/groups"
GET_ZONES_ENDPOINT = "/api/v1/zones"
LIST_GROUP_ENDPOINT = "/api/v1/groups"
LIST_LOGS_ENDPOINT = "/api/v1/logs"
REMOVE_USER_FROM_GROUP_ENDPOINT = "/api/v1/groups/{group_id}/users/{user_id}"
RESET_FACTORS_ENDPOINT = "/api/v1/users/{user_id}/lifecycle/reset_factors"
RESET_PASSWORD_ENDPOINT = "/api/v1/users/{user_id}/lifecycle/expire_password"  # nosec bandit B105
SEND_PUSH_ENDPOINT = "/api/v1/users/{user_id}/factors/{factor_id}/verify"
SUSPEND_USER_ENDPOINT = "/api/v1/users/{user_id}/lifecycle/suspend"
UNSUSPEND_USER_ENDPOINT = "/api/v1/users/{user_id}/lifecycle/unsuspend"
UPDATE_ZONE_ENDPOINT = "/api/v1/zones/{zone_id}"
USER_ENDPOINT = "/api/v1/users/{user_id}"
USERS_ENDPOINT = "/api/v1/users"
USERS_IN_GROUP_ENDPOINT = "/api/v1/groups/{group_id}/users"
GROUP_ENDPOINT = "/api/v1/groups/{group_id}"
