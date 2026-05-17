import numpy as np
import pandas as pd
import json
import pickle
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
import lightgbm as lgb
from pe_extractor import PEFeatureExtractor

def generate_synthetic_data(num_samples=5000):
    print(f"Generating {num_samples} synthetic PE samples...")
    extractor = PEFeatureExtractor()
    dim = extractor.dim  # 2381
    
    np.random.seed(42)
    X = np.random.normal(loc=0.0, scale=1.0, size=(num_samples, dim))
    y = np.random.randint(0, 2, size=num_samples)
    
    # Let's add some structured differences based on label y to make the models learn
    # GeneralFileInfo indices (index 512 to 625 approx, let's verify):
    # ByteHistogram: 0-255
    # ByteEntropyHistogram: 256-511
    # StringExtractor: 512-615
    # GeneralFileInfo: 616-625 (size, vsize, has_debug, exports, imports, has_relocations, has_resources, has_signature, has_tls, symbols)
    
    # 1. has_signature is at index 623
    sig_idx = 623
    X[y == 0, sig_idx] = np.random.choice([0.0, 1.0], size=sum(y == 0), p=[0.1, 0.9]) # Benign mostly signed
    X[y == 1, sig_idx] = np.random.choice([0.0, 1.0], size=sum(y == 1), p=[0.8, 0.2]) # Malware mostly unsigned
    
    # 2. has_debug is at index 618
    debug_idx = 618
    X[y == 0, debug_idx] = np.random.choice([0.0, 1.0], size=sum(y == 0), p=[0.2, 0.8]) # Benign has debug
    X[y == 1, debug_idx] = np.random.choice([0.0, 1.0], size=sum(y == 1), p=[0.9, 0.1]) # Malware lacks debug
    
    # 3. String count (index 512)
    str_idx = 512
    X[y == 0, str_idx] = np.random.normal(loc=150.0, scale=30.0, size=sum(y == 0))
    X[y == 1, str_idx] = np.random.normal(loc=400.0, scale=100.0, size=sum(y == 1))
    
    # 4. Section entropy indicators in SectionInfo (index 717 to 971, let's add bias to a few)
    for ent_idx in range(717 + 5, 717 + 55): # First few hashed section entropy dimensions
        X[y == 0, ent_idx] = np.random.normal(loc=3.5, scale=0.8, size=sum(y == 0))
        X[y == 1, ent_idx] = np.random.normal(loc=6.8, scale=0.5, size=sum(y == 1))
        
    # Let's make exactly 41 columns constant (value = 0.0) so they get removed in the preprocessing step
    constant_cols_indices = np.random.choice(range(dim), size=41, replace=False)
    # Exclude our engineered indices
    constant_cols_indices = [idx for idx in constant_cols_indices if idx not in [sig_idx, debug_idx, str_idx]]
    constant_cols_indices = constant_cols_indices[:41]
    
    for idx in constant_cols_indices:
        X[:, idx] = 0.0
        
    return X, y, constant_cols_indices

def train_and_save():
    X, y, constant_cols = generate_synthetic_data()
    
    # Create DataFrame to match columns name formatting F1, F2...
    df = pd.DataFrame(X, columns=[f"F{i+1}" for i in range(X.shape[1])])
    
    # Step 1: Preprocessing - Filter out constant columns
    constant_cols_names = [f"F{idx+1}" for idx in constant_cols]
    print(f"Dropping {len(constant_cols_names)} constant columns...")
    df_filtered = df.drop(columns=constant_cols_names)
    
    # Step 2: Feature Selection using LightGBM
    print("Running feature selection using LightGBM importance...")
    X_f = df_filtered.copy()
    y_f = y
    
    selector_model = lgb.LGBMClassifier(n_estimators=50, random_state=42, verbose=-1, n_jobs=-1)
    selector_model.fit(X_f, y_f)
    
    importances = selector_model.feature_importances_
    importance_df = pd.DataFrame({
        'Feature': X_f.columns,
        'Importance': importances
    }).sort_values(by='Importance', ascending=False)
    
    # Select top 200 features
    top_200 = list(importance_df['Feature'].head(200))
    print(f"Selected Top 200 features! E.g. {top_200[:10]}")
    
    # Save top 200 features
    with open('top_200_features.json', 'w') as f:
        json.dump(top_200, f, indent=2)
    print("Saved top_200_features.json")
    
    # Slice features
    X_selected = df_filtered[top_200]
    
    # Split
    X_train, X_val, y_train, y_val = train_test_split(X_selected, y, test_size=0.2, random_state=42)
    
    # Scaler
    print("Fitting StandardScaler...")
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_val_scaled = scaler.transform(X_val)
    
    with open('scaler.pkl', 'wb') as f:
        pickle.dump(scaler, f)
    print("Saved scaler.pkl")
    
    # Train Models
    print("Training Logistic Regression...")
    lr = LogisticRegression(max_iter=1000, random_state=42)
    lr.fit(X_train_scaled, y_train)
    with open('model_lr.pkl', 'wb') as f:
        pickle.dump(lr, f)
        
    print("Training Random Forest...")
    rf = RandomForestClassifier(n_estimators=100, n_jobs=-1, random_state=42)
    rf.fit(X_train_scaled, y_train)
    with open('model_rf.pkl', 'wb') as f:
        pickle.dump(rf, f)
        
    print("Training LightGBM...")
    lgb_clf = lgb.LGBMClassifier(n_estimators=500, learning_rate=0.05, random_state=42, n_jobs=-1, verbose=-1)
    lgb_clf.fit(X_train_scaled, y_train)
    with open('model_lgb.pkl', 'wb') as f:
        pickle.dump(lgb_clf, f)
        
    print("All models and scalers saved successfully!")

if __name__ == '__main__':
    train_and_save()
