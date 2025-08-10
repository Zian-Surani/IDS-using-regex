import os, requests, joblib
import numpy as np
import pandas as pd
from sklearn.preprocessing import OneHotEncoder, StandardScaler
from sklearn.model_selection import train_test_split
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense
from tensorflow.keras.optimizers import Adam

os.makedirs("model", exist_ok=True)
os.makedirs("preprocessors", exist_ok=True)

TRAIN_URL = "https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTrain+.txt"
TEST_URL  = "https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTest+.txt"

def download_if_missing(url, path):
    if not os.path.exists(path):
        print(f"Downloading {url} -> {path}")
        r = requests.get(url)
        r.raise_for_status()
        with open(path, "wb") as f:
            f.write(r.content)

download_if_missing(TRAIN_URL, "KDDTrain+.txt")
download_if_missing(TEST_URL,  "KDDTest+.txt")

columns = ['duration','protocol_type','service','flag','src_bytes','dst_bytes','land','wrong_fragment','urgent','hot',
           'num_failed_logins','logged_in','num_compromised','root_shell','su_attempted','num_root','num_file_creations',
           'num_shells','num_access_files','num_outbound_cmds','is_host_login','is_guest_login','count','srv_count',
           'serror_rate','srv_serror_rate','rerror_rate','srv_rerror_rate','same_srv_rate','diff_srv_rate',
           'srv_diff_host_rate','dst_host_count','dst_host_srv_count','dst_host_same_srv_rate','dst_host_diff_srv_rate',
           'dst_host_same_src_port_rate','dst_host_srv_diff_host_rate','dst_host_serror_rate','dst_host_srv_serror_rate',
           'dst_host_rerror_rate','dst_host_srv_rerror_rate','label','difficulty']

df_train = pd.read_csv("KDDTrain+.txt", header=None, names=columns)
df_test  = pd.read_csv("KDDTest+.txt",  header=None, names=columns)
print("Loaded datasets")

df_train["attack"] = (df_train["label"] != "normal").astype(int)
df_test["attack"]  = (df_test["label"]  != "normal").astype(int)

X_train = df_train.drop(columns=["label","difficulty","attack"])
y_train = df_train["attack"]
X_test  = df_test.drop(columns=["label","difficulty","attack"])
y_test  = df_test["attack"]

cat_cols = ["protocol_type","service","flag"]
num_cols = [c for c in X_train.columns if c not in cat_cols]

# IMPORTANT: for sklearn >=1.2 use sparse_output=False
ohe = OneHotEncoder(handle_unknown="ignore", sparse_output=False)
ohe.fit(X_train[cat_cols])

scaler = StandardScaler()
scaler.fit(X_train[num_cols])

X_tr = np.hstack([scaler.transform(X_train[num_cols]), ohe.transform(X_train[cat_cols])])
X_te = np.hstack([scaler.transform(X_test[num_cols]),  ohe.transform(X_test[cat_cols])])

print("Preprocessing done. Shape:", X_tr.shape)

joblib.dump(ohe, "preprocessors/ohe.pkl")
joblib.dump(scaler, "preprocessors/scaler.pkl")

model = Sequential([
    Dense(256, activation="relu", input_shape=(X_tr.shape[1],)),
    Dense(128, activation="relu"),
    Dense(1, activation="sigmoid")
])
model.compile(optimizer=Adam(1e-3), loss="binary_crossentropy", metrics=["accuracy"])
model.fit(X_tr, y_train, epochs=8, batch_size=512, validation_data=(X_te, y_test))
model.save("model/ann_model.h5")
print("Model trained and saved to model/ann_model.h5")
