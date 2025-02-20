resource "auth0_tenant" "tenant_config" {
  friendly_name = "Amin's playground"
  flags {
    enable_client_connections = false
  }
}

data "auth0_resource_server" "api_v2" {
  identifier = "https://${var.auth0_domain}/api/v2/"
}


# Users DB
resource "auth0_connection" "users" {
  name     = "Users"
  strategy = "auth0"

  options {
    requires_username      = false
    password_policy        = "low"
    disable_signup         = false
    brute_force_protection = true
  }
}

data "auth0_connection" "google-social" {
  name     = "google-oauth2"
}

data "auth0_connection" "facebook" {
  name     = "facebook"
}

# simple SPA client
resource "auth0_client" "spa" {
  name            = "JWT.io"
  description     = "JWT client"
  app_type        = "spa"
  oidc_conformant = true
  is_first_party  = true

  grant_types = [
    "implicit"
  ]

  callbacks = [
    "https://jwt.io"
  ]

  allowed_logout_urls = [
  ]

  jwt_configuration {
    alg = "RS256"
  }
}

# RWA app that initiates account linking
resource "auth0_client" "outer_client" {
  name            = "openidconnect.net"
  description     = "Account Linking Demo Outer client"
  app_type        = "regular_web"
  oidc_conformant = true
  is_first_party  = true
  require_pushed_authorization_requests = true

  grant_types = [
    "authorization_code"
  ]

  callbacks = [
    "https://jwt.io",
    "https://openidconnect.net/callback",
  ]

  allowed_logout_urls = [
  ]

  jwt_configuration {
    alg = "RS256"
  }
}

# Connection vs Clients
resource "auth0_connection_clients" "users_clients" {
  connection_id = auth0_connection.users.id
  enabled_clients = [
    auth0_client.spa.id,
    auth0_client.outer_client.id,
    var.auth0_tf_client_id,
    auth0_client.par_linking_companion_app.id
  ]
}

resource "auth0_connection_clients" "google_clients" {
  connection_id = data.auth0_connection.google-social.id
  enabled_clients = [
    auth0_client.spa.id,
    auth0_client.outer_client.id,
    auth0_client.par_linking_companion_app.id
  ]
  /*
  lifecycle {
    ignore_changes = [enabled_clients]
  }
  */
}

resource "auth0_connection_clients" "facebook_clients" {
  connection_id = data.auth0_connection.facebook.id
  enabled_clients = [
    auth0_client.spa.id,
    auth0_client.outer_client.id,
    auth0_client.par_linking_companion_app.id
  ]
  /*
  lifecycle {
    ignore_changes = [enabled_clients]
  }
  */
}

## Users
resource "auth0_user" "user_1" {
  depends_on = [auth0_connection_clients.users_clients]
  connection_name = auth0_connection.users.name
  email           = "user1@atko.email"
  password        = var.default_password
}

## outputs
output "spa_id" {
  value = auth0_client.spa.client_id
}

output "outer_client_id" {
  value = auth0_client.outer_client.client_id
}

output "spa_login_url" {
  value = join("&", [
    "https://${var.auth0_domain}/authorize?client_id=${auth0_client.spa.id}",
    "response_type=code",
    "redirect_uri=${urlencode(auth0_client.spa.callbacks[0])}",
    "login_hint=${urlencode(auth0_user.user_1.email)}",
    "scope=${urlencode("openid profile email")}",
    "nonce=n1",
    "state=s1",
  ]
  )
}

