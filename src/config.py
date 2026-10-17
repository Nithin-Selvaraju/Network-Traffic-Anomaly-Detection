"""
Configuration file for Network Traffic Anomaly Detection ML System.
Contains feature column definitions, 5-class attack mappings, and model hyperparameters
matching the patent specification.
"""

from pathlib import Path

# Base Paths
BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR
OUTPUTS_DIR = BASE_DIR / "outputs"
FIGURES_DIR = OUTPUTS_DIR / "figures"
MODELS_DIR = OUTPUTS_DIR / "models"

# Dataset File Paths
TRAIN_DATA_PATH = DATA_DIR / "KDDTrain+.txt"
TEST_DATA_PATH = DATA_DIR / "KDDTest+.txt"

# 41 NSL-KDD Features categorized according to the Patent Specification
FEATURE_CATEGORIES = {
    "basic": [
        "duration", "protocol_type", "service", "flag", "src_bytes",
        "dst_bytes", "land", "wrong_fragment", "urgent"
    ],
    "content": [
        "hot", "num_failed_logins", "logged_in", "num_compromised",
        "root_shell", "su_attempted", "num_root", "num_file_creations",
        "num_shells", "num_access_files", "num_outbound_cmds",
        "is_host_login", "is_guest_login"
    ],
    "time_based": [
        "count", "srv_count", "serror_rate", "srv_serror_rate",
        "rerror_rate", "srv_rerror_rate", "same_srv_rate",
        "diff_srv_rate", "srv_diff_host_rate"
    ],
    "host_based": [
        "dst_host_count", "dst_host_srv_count", "dst_host_same_srv_rate",
        "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
        "dst_host_srv_diff_host_rate", "dst_host_serror_rate",
        "dst_host_srv_serror_rate", "dst_host_rerror_rate",
        "dst_host_srv_rerror_rate"
    ]
}

# Full column list for raw NSL-KDD files (41 features + label + difficulty score = 43 columns)
ALL_COLUMNS = (
    FEATURE_CATEGORIES["basic"]
    + FEATURE_CATEGORIES["content"]
    + FEATURE_CATEGORIES["time_based"]
    + FEATURE_CATEGORIES["host_based"]
    + ["label", "difficulty"]
)

# Categorical and Numerical features
CATEGORICAL_FEATURES = ["protocol_type", "service", "flag"]
NUMERICAL_FEATURES = [
    col for col in (
        FEATURE_CATEGORIES["basic"]
        + FEATURE_CATEGORIES["content"]
        + FEATURE_CATEGORIES["time_based"]
        + FEATURE_CATEGORIES["host_based"]
    ) if col not in CATEGORICAL_FEATURES
]

FEATURE_COLS_41 = (
    FEATURE_CATEGORIES["basic"]
    + FEATURE_CATEGORIES["content"]
    + FEATURE_CATEGORIES["time_based"]
    + FEATURE_CATEGORIES["host_based"]
)

# NSL-KDD 5-Class Attack Taxonomy Mapping
ATTACK_MAPPING = {
    "normal": "Normal",
    # DoS Attacks
    "neptune": "DoS",
    "back": "DoS",
    "land": "DoS",
    "pod": "DoS",
    "smurf": "DoS",
    "teardrop": "DoS",
    "mailbomb": "DoS",
    "apache2": "DoS",
    "processtable": "DoS",
    "udpstorm": "DoS",
    # Probe Attacks
    "ipsweep": "Probe",
    "nmap": "Probe",
    "portsweep": "Probe",
    "satan": "Probe",
    "mscan": "Probe",
    "saint": "Probe",
    # R2L Attacks
    "ftp_write": "R2L",
    "guess_passwd": "R2L",
    "imap": "R2L",
    "multihop": "R2L",
    "phf": "R2L",
    "spy": "R2L",
    "warezclient": "R2L",
    "warezmaster": "R2L",
    "sendmail": "R2L",
    "named": "R2L",
    "snmpgetattack": "R2L",
    "snmpguess": "R2L",
    "xlock": "R2L",
    "xsnoop": "R2L",
    "httptunnel": "R2L",
    # U2R Attacks
    "buffer_overflow": "U2R",
    "loadmodule": "U2R",
    "perl": "U2R",
    "rootkit": "U2R",
    "ps": "U2R",
    "sqlattack": "U2R",
    "xterm": "U2R",
}

# Model Hyperparameters as specified in patent
ISOLATION_FOREST_PARAMS = {
    "n_estimators": 100,
    "contamination": 0.3,
    "random_state": 42,
    "n_jobs": -1
}

KMEANS_PARAMS = {
    "n_clusters": 2,
    "n_init": 10,
    "random_state": 42
}

RANDOM_FOREST_PARAMS = {
    "n_estimators": 100,
    "criterion": "gini",
    "random_state": 42,
    "n_jobs": -1
}
