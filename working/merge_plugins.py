import pandas as pd
import numpy as np
import os

def merge_plugin_csvs(input_path="clean_csv_outputs", output_path="merged_csv_outputs", log=None):
    if log: log("🔄 Starting merge of plugin CSVs...")

    os.makedirs(output_path, exist_ok=True)

    def safe_read_csv(filename):
        path = os.path.join(input_path, filename)
        try:
            with open(path, 'r', encoding='utf-8-sig', errors='replace') as f:
                df = pd.read_csv(f, dtype=str)  # ✅ Always keep as string to preserve full timestamps
            if log: log(f"✅ Loaded {filename} ({len(df)} rows)")
            return df
        except Exception as e:
            if log: log(f"⚠️ Could not read {filename}: {e}")
            return pd.DataFrame()

    pslist = safe_read_csv("windows_pslist.csv")
    if pslist.empty:
        return False, "pslist.csv is empty or missing"

    cmdline = safe_read_csv("windows_cmdline.csv")
    dlllist = safe_read_csv("windows_dlllist.csv")
    psscan = safe_read_csv("windows_psscan.csv")
    handles = safe_read_csv("windows_handles.csv")
    malfind = safe_read_csv("windows_malfind.csv")
    callbacks = safe_read_csv("windows_callbacks.csv")
    hollow = safe_read_csv("windows_hollowprocesses.csv")
    ldrmodules = safe_read_csv("windows_ldrmodules.csv")
    netscan = safe_read_csv("windows_netscan.csv")
    pstree = safe_read_csv("windows_pstree.csv")
    registry = safe_read_csv("windows_registry_hivelist.csv")
    susp_threads = safe_read_csv("windows_suspicious_threads.csv")

    if log: log("📊 Cleaning PID columns...")

    all_plugins = [pslist, dlllist, handles, psscan, cmdline, callbacks, hollow,
                   ldrmodules, netscan, pstree, registry, susp_threads, malfind]

    for df in all_plugins:
        if 'PID' in df.columns:
            df['PID'] = pd.to_numeric(df['PID'], errors='coerce')
            df.dropna(subset=['PID'], inplace=True)
            df['PID'] = df['PID'].astype(int)

    malfind.columns = malfind.columns.str.strip()

    if log: log("🧠 Building base feature set from pslist...")

    possible_name_cols = ['Process', 'ImageFileName', 'Name']
    name_col = next((col for col in possible_name_cols if col in pslist.columns), None)

    if name_col:
        features_df = pslist[['PID', name_col, 'PPID', 'Threads']].copy()
        features_df.rename(columns={name_col: 'Process'}, inplace=True)
    else:
        features_df = pslist[['PID', 'PPID', 'Threads']].copy()
        features_df['Process'] = 'Unknown'

    # ✅ EXACT: Use CreateTime and ExitTime directly
    if 'CreateTime' in pslist.columns:
        features_df['CreateTime'] = pslist['CreateTime'].fillna('N/A')
    else:
        features_df['CreateTime'] = 'N/A'

    if 'ExitTime' in pslist.columns:
        features_df['EndTime'] = pslist['ExitTime'].fillna('N/A')
    else:
        features_df['EndTime'] = 'N/A'

    # ✅ Add Args if present
    if 'Args' in cmdline.columns:
        features_df = features_df.merge(
            cmdline[['PID', 'Args']],
            on='PID',
            how='left'
        )
        features_df['Args'].fillna('N/A', inplace=True)
    else:
        features_df['Args'] = 'N/A'

    if features_df.empty:
        if log: log("❌ No valid processes found in pslist.csv")
        return False, "No valid processes found"

    merge_steps = {
        'malfind_count': malfind,
        'dll_count': dlllist,
        'handle_count': handles,
        'psscan_count': psscan,
        'cmdline_count': cmdline,
        'callbacks_count': callbacks,
        'hollow_count': hollow,
        'ldrmodule_count': ldrmodules,
        'netscan_count': netscan,
        'pstree_count': pstree,
        'registry_count': registry,
        'suspicious_threads_count': susp_threads
    }

    if log: log("🔗 Merging feature counts from plugins...")

    for feature_name, plugin_df in merge_steps.items():
        if 'PID' in plugin_df.columns:
            count_series = plugin_df.groupby('PID').size().rename(feature_name)
            features_df = features_df.merge(count_series, on='PID', how='left')

    features_df.fillna(0, inplace=True)

    if log: log("💾 Saving merged CSV files...")

    merged_path = os.path.join(output_path, "merged_features.csv")
    ml_path = os.path.join(output_path, "ml_ready_features.csv")

    features_df.to_csv(merged_path, index=False, encoding='utf-8-sig')

    ml_df = features_df.drop(columns=['Process', 'CreateTime', 'EndTime', 'Args'], errors='ignore')
    ml_df = ml_df.apply(pd.to_numeric, errors='coerce')
    ml_df.fillna(0, inplace=True)
    ml_df.to_csv(ml_path, index=False, encoding='utf-8-sig')

    if log: log("✅ Merging completed successfully!")
    return True, "Merging completed successfully"
