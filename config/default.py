CONFIGURATION_PROFILE = "default"

### IAM SETTINGS
IAM_CLIENT_ID = "XXX-XXX-XXX-XXX-XXX"
IAM_CLIENT_SECRET = "************"
IAM_BASE_URL = "https://iam.example.com"
EGI_AAI_BASE_URL="https://https://aai-dev.egi.eu/oidc/"
EGI_AAI_CLIENT_ID=""
EGI_AAI_CLIENT_SECRET=""

TRUSTED_OIDC_IDP_LIST = [ { 'iss': 'https://iam.example.org/', 'type': 'indigoiam' } ]

ORCHESTRATOR_URL = "https://orchestrator.example.com"
CALLBACK_URL = "https://dashboard.example.com/home/callback"

### TOSCA-related SETTINGS
TOSCA_TEMPLATES_DIR = "/opt/tosca-templates"
TOSCA_PARAMETERS_DIR = "/opt/tosca-parameters"
TOSCA_METADATA_DIR = "/opt/tosca-metadata"

### DB SETTINGS
SQLALCHEMY_DATABASE_URI = "mysql+pymysql://oduser:oduser@localhost/orchestrator_dashboard_test",
SQLALCHEMY_TRACK_MODIFICATIONS = "False"
SQLALCHEMY_VERSION_HEAD = "88bc3c2c02a6"

### NOTIFICATION SETTINGS
MAIL_SERVER = "relay-mbox.recas.ba.infn.it"
MAIL_PORT = "25"
MAIL_DEFAULT_SENDER = "admin@orchestrator-dashboard"
MAIL_USERNAME = None
MAIL_PASSWORD = None
MAIL_DEBUG = False

### YOURLS SETTINGS
YOURLS_SITE = None
YOURLS_API_SIGNATURE_TOKEN=None

### ADMIN SETTINGS
SUPPORT_EMAIL = "marica.antonacci@ba.infn.it"
ADMINS = "['marica.antonacci@ba.infn.it']"
EXTERNAL_LINKS = []
OVERALL_TIMEOUT = 720
PROVIDER_TIMEOUT = 720
LOG_LEVEL = "info"
UPLOAD_FOLDER = "/tmp"

ENABLE_ADVANCED_MENU = "yes"
FEATURE_UPDATE_DEPLOYMENT = "no"
FEATURE_HIDDEN_DEPLOYMENT_COLUMNS = "4, 5, 7"
FEATURE_VAULT_INTEGRATION = "no"

### VAULT INTEGRATION SETTINGS
VAULT_ROLE = "orchestrator"
VAULT_OIDC_AUDIENCE = "ff2c57dc-fa09-43c9-984e-9ad8afc3fb56"

#### LOOK AND FEEL SETTINGS
WELCOME_MESSAGE = "Welcome! This is the PaaS Orchestrator Dashboard"
NAVBAR_BRAND_TEXT = "PaaS Orchestrator Dashboard"
NAVBAR_BRAND_ICON = "/home/static/images/indigodc_logo.png"
FAVICON_PATH = "/home/static/images/favicon_io"
MAIL_IMAGE_SRC = "https://raw.githubusercontent.com/maricaantonacci/orchestrator-dashboard/stateful/app/home/static/images/orchestrator-logo.png"

### Template Paths
HOME_TEMPLATE = 'home.html'
PORTFOLIO_TEMPLATE = 'portfolio.html'
MAIL_TEMPLATE = 'email.html'
FOOTER_TEMPLATE = 'footer.html'
