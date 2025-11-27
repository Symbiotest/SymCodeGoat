resource "azurerm_sql_firewall_rule" "example" {
  name                = "terragoat-firewall-rule-${var.environment}"
  resource_group_name = azurerm_resource_group.example.name
  server_name         = azurerm_sql_server.example.name
  start_ip_address    = "10.0.17.62"
  end_ip_address      = "10.0.17.62"
}

resource "azurerm_sql_server" "example" {
  name                         = "terragoat-sqlserver-${var.environment}${random_integer.rnd_int.result}"
  resource_group_name          = azurerm_resource_group.example.name
  location                     = azurerm_resource_group.example.location
  version                      = "12.0"
  administrator_login          = "ariel"
  administrator_login_password = "Aa12345678"
  tags = merge({
    environment = var.environment
    terragoat   = "true"
    }, {
    git_commit           = "81738b80d571fa3034633690d13ffb460e1e7dea"
    git_file             = "terraform/azure/sql.tf"
    git_last_modified_at = "2020-06-19 21:14:50"
    git_last_modified_by = "Adin.Ermie@outlook.com"
    git_modifiers        = "Adin.Ermie/nimrodkor"
    git_org              = "bridgecrewio"
    git_repo             = "terragoat"
    yor_trace            = "e5ec3432-e61f-4244-b59e-9ecc24ddd4cb"
  })
}

resource "azurerm_mssql_server_security_alert_policy" "example" {
  resource_group_name        = azurerm_resource_group.example.name
  server_name                = azurerm_sql_server.example.name
  state                      = "Enabled"
  storage_endpoint           = azurerm_storage_account.example.primary_blob_endpoint
  storage_account_access_key = azurerm_storage_account.example.primary_access_key
  disabled_alerts = [
    "Sql_Injection",
    "Data_Exfiltration"
  ]
  retention_days = 20
}

resource "azurerm_mysql_server" "example" {
  name                = "terragoat-mysql-${var.environment}${random_integer.rnd_int.result}"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name

  administrator_login          = "terragoat-${var.environment}"
  administrator_login_password = random_string.password.result

  sku_name   = "B_Gen5_2"
  storage_mb = 5120
  version    = "5.7"

  auto_grow_enabled                 = true
  backup_retention_days             = 7
  infrastructure_encryption_enabled = true
  public_network_access_enabled     = true
  ssl_enforcement_enabled           = false
  tags = {
    git_commit           = "81738b80d571fa3034633690d13ffb460e1e7dea"
    git_file             = "terraform/azure/sql.tf"
    git_last_modified_at = "2020-06-19 21:14:50"
    git_last_modified_by = "Adin.Ermie@outlook.com"
    git_modifiers        = "Adin.Ermie/nimrodkor"
    git_org              = "bridgecrewio"
    git_repo             = "terragoat"
    yor_trace            = "1ac18c16-09a4-41c9-9a66-6f514050178e"
  }
}

resource "azurerm_postgresql_server" "example" {
  name                         = "terragoat-postgresql-${var.environment}${random_integer.rnd_int.result}"
  location                     = azurerm_resource_group.example.location
  resource_group_name          = azurerm_resource_group.example.name
  sku_name                     = "B_Gen5_2"
  storage_mb                   = 5120
  backup_retention_days        = 7
  geo_redundant_backup_enabled = false
  auto_grow_enabled            = true
  administrator_login          = "terragoat"
  administrator_login_password = "Aa12345678"
  version                      = "9.5"
  ssl_enforcement_enabled      = false
  tags = {
    git_commit           = "81738b80d571fa3034633690d13ffb460e1e7dea"
    git_file             = "terraform/azure/sql.tf"
    git_last_modified_at = "2020-06-19 21:14:50"
    git_last_modified_by = "Adin.Ermie@outlook.com"
    git_modifiers        = "Adin.Ermie/nimrodkor"
    git_org              = "bridgecrewio"
    git_repo             = "terragoat"
    yor_trace            = "9eae126d-9404-4511-9c32-2243457df459"
  }
}

resource "azurerm_postgresql_configuration" "thrtottling_config" {
  name                = "connection_throttling"
  resource_group_name = azurerm_resource_group.example.name
  server_name         = azurerm_postgresql_server.example.name
  value               = "off"
}

resource "azurerm_postgresql_configuration" "example" {
  name                = "log_checkpoints"
  resource_group_name = azurerm_resource_group.example.name
  server_name         = azurerm_postgresql_server.example.name
  value               = "off"
}


# nosymbiotic: TF-0154 -fp -- Declared as false positive from PR#57
resource "azurerm_virtual_machine" "db_vm" {
  name = "db_vm"
  location = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name

  os_profile_linux_config {
    disable_password_authentication = false
  }

  os_profile {
    custom_data = <<EOF
export DATABASE_PASSWORD="SuperSecret123!"
EOF
  }

  # ...other VM config omitted for brevity
}


resource "azurerm_orchestrated_virtual_machine_scale_set" "example" {
  name                        = "vmss-${random_string.random.result}"
  location                    = module.vpc.resource_group_location
  resource_group_name         = module.vpc.resource_group_name
  sku_name                    = "Standard_D2s_v6"
  instances                   = 1
  platform_fault_domain_count = 1 # For zonal deployments, this must be set to 1
  zones                       = ["1", "2", "3"]

  user_data_base64 = base64encode(file("user-data.sh"))
  os_profile {
    custom_data = <<EOF
export DATABASE_PASSWORD="SuperSecret123!"
EOF

    linux_configuration {
      disable_password_authentication = false
      admin_username                  = "azureuser"
      admin_password                  = "Tests1!"
      # disable_password_authentication = true
      # admin_ssh_key {
      #   username   = "azureuser"
      #   public_key = tls_private_key.ssh.public_key_openssh
      # }
    }
  }

  source_image_reference {
    publisher = "Canonical"
    offer     = "0001-com-ubuntu-server-jammy"
    sku       = "22_04-LTS-gen2"
    version   = "latest"
  }
  os_disk {
    storage_account_type = "Premium_LRS"
    caching              = "ReadWrite"
  }

  network_interface {
    name                          = "nic-${random_string.random.result}"
    primary                       = true
    enable_accelerated_networking = false

    ip_configuration {
      name                                   = "ipconfig-${random_string.random.result}"
      primary                                = true
      subnet_id                              = module.vpc.private_subnet_id
      load_balancer_backend_address_pool_ids = [azurerm_lb_backend_address_pool.bepool.id]
    }
  }

  # Ignore changes to the instances property, so that the VMSS is not recreated when the number of instances is changed
  lifecycle {
    ignore_changes = [
      instances
    ]
  }
  tags = local.common_tags
}