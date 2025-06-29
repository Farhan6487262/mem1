from flask import Flask, render_template, request, redirect, url_for, Response
from flask_login import LoginManager, login_user, logout_user, login_required, UserMixin, current_user
import os
import subprocess
import threading
import time
import pandas as pd
import requests
import sys
import io
import queue

from merge_plugins import merge_plugin_csvs
from predictor import run_prediction













sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

app = Flask(__name__)
app.secret_key = 'supersecretkey'

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'index'

USERS = {'admin': 'admin'}

class User(UserMixin):
    def __init__(self, id):
        self.id = id

@login_manager.user_loader
def load_user(user_id):
    if user_id in USERS:
        return User(user_id)
    return None

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
MEMORY_DUMP_PATH = os.path.join(BASE_DIR, "memory_dump.dmp")

# Example: where to save the dump
#MEMORY_DUMP_PATH = os.path.join("uploads", "memory_dump.dmp")
#DUMP_ORIGIN_PATH = os.path.join("uploads", "dump_origin.txt")
DUMP_ORIGIN_PATH = os.path.join(BASE_DIR, "dump_origin.txt")



UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
PLUGIN_OUTPUT_DIR = os.path.join(BASE_DIR, "plugin_outputs")
CSV_OUTPUT_DIR = os.path.join(BASE_DIR, "clean_csv_outputs")
VOLATILITY_PATH = r"D:\AIMODELSPROJECT\projects\sir sarfaraz fiver\working\vol4\volatility3\vol.py"
WINPMEM_EXE = os.path.join(BASE_DIR, "winpmem.exe")
output_path = "merged_csv_outputs"

os.makedirs(output_path, exist_ok=True)
os.makedirs(PLUGIN_OUTPUT_DIR, exist_ok=True)
os.makedirs(CSV_OUTPUT_DIR, exist_ok=True)
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

sse_messages = []
message_queues = []

def send_sse_message(message):
    sse_messages.append(message)
    for q in message_queues:
        q.put(message)

def stream_sse():
    last_index = 0
    while True:
        while len(sse_messages) > last_index:
            msg = sse_messages[last_index]
            last_index += 1
            yield f"data: {msg}\n\n"
        time.sleep(0.5)

def download_winpmem():
    try:
        send_sse_message("🌐 Checking latest WinPMEM release...")
        api_url = "https://api.github.com/repos/Velocidex/WinPmem/releases/latest"
        headers = {"Accept": "application/vnd.github.v3+json"}

        response = requests.get(api_url, headers=headers)
        if response.status_code != 200:
            send_sse_message(f"❌ GitHub API error: {response.status_code}")
            return False

        data = response.json()
        for asset in data.get("assets", []):
            if "winpmem" in asset["name"].lower() and asset["name"].endswith(".exe"):
                download_url = asset["browser_download_url"]
                send_sse_message(f"⬇️ Downloading {asset['name']}...")

                with requests.get(download_url, stream=True) as r:
                    r.raise_for_status()
                    with open(WINPMEM_EXE, 'wb') as f:
                        for chunk in r.iter_content(chunk_size=8192):
                            f.write(chunk)

                send_sse_message("✅ WinPMEM downloaded successfully.")
                return True

        send_sse_message("❌ No suitable WinPMEM asset found in release.")
        return False

    except Exception as e:
        send_sse_message(f"❌ Exception during download: {str(e)}")
        return False

def create_memory_dump():
    if not os.path.exists(WINPMEM_EXE):
        if not download_winpmem():
            send_sse_message("❌ Could not proceed without WinPMEM.")
            return

    send_sse_message("🔧 Creating memory dump using WinPMEM...")
    try:
        
        with open(DUMP_ORIGIN_PATH, 'w') as f:
            f.write('Generated by MemScan')

        # ✅ Actually create the dump file — adapt this to your tool:
        #os.system(f"DumpIt.exe -o {MEMORY_DUMP_PATH}")
        
        
        cmd = [WINPMEM_EXE, "acquire", MEMORY_DUMP_PATH]
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        for line in proc.stdout:
            send_sse_message(line.strip())
        proc.wait()
        if proc.returncode == 0:
            send_sse_message(f"✅ Memory dump created at {MEMORY_DUMP_PATH}")
        else:
            send_sse_message("❌ Memory dump creation failed.")
    except Exception as e:
        send_sse_message(f"❌ Error: {str(e)}")

def run_volatility_plugins():
    plugins = [
        "windows.pslist", 
        "windows.cmdline",
        "windows.psscan", "windows.pstree",
        "windows.dlllist", "windows.netscan", "windows.malfind", "windows.handles",
        "windows.ldrmodules", "windows.modules", "windows.suspicious_threads",
        "windows.hollowprocesses", "windows.callbacks", "windows.registry.hivelist"
    ]
    for plugin in plugins:
        send_sse_message(f"🔍 Running {plugin}...")
        try:
            output_file = os.path.join(PLUGIN_OUTPUT_DIR, f"{plugin.replace('.', '_')}.txt")
            cmd = ["python", VOLATILITY_PATH, "-f", MEMORY_DUMP_PATH, plugin]
            result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            cleaned_output = "\n".join([
                line for line in result.stdout.splitlines()
                if not line.startswith("Volatility 3 Framework") and line.strip()
            ])
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(cleaned_output)
            send_sse_message(f"✅ {plugin} completed.")
        except Exception as e:
            send_sse_message(f"❌ Error running {plugin}: {str(e)}")

def convert_txt_to_csv():
    os.makedirs(CSV_OUTPUT_DIR, exist_ok=True)
    send_sse_message("📄 Converting TXT to CSV...")
    for file in os.listdir(PLUGIN_OUTPUT_DIR):
        if file.endswith(".txt"):
            txt_path = os.path.join(PLUGIN_OUTPUT_DIR, file)
            csv_path = os.path.join(CSV_OUTPUT_DIR, file.replace(".txt", ".csv"))
            try:
                with open(txt_path, "r", encoding="utf-8", errors="ignore") as f:
                    lines = [line.strip() for line in f if line.strip() and not line.lower().startswith("volatility")]
                if len(lines) < 2:
                    send_sse_message(f"⚠️ Skipped {file}, not enough data.")
                    continue
                headers = lines[0].split()
                rows = []
                for line in lines[1:]:
                    parts = line.split(None, len(headers) - 1)
                    if len(parts) == len(headers):
                        rows.append(parts)
                pd.DataFrame(rows, columns=headers).to_csv(csv_path, index=False)
                send_sse_message(f"✅ Converted {file} to CSV.")
            except Exception as e:
                send_sse_message(f"❌ Error converting {file}: {str(e)}")
    send_sse_message("📁 All conversions completed.")

@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('login.html')

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    if USERS.get(username) == password:
        login_user(User(username))
        return redirect(url_for('dashboard'))
    return "Invalid login", 401

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('index.html')

@app.route('/sse')
@login_required
def sse():
    return Response(stream_sse(), mimetype='text/event-stream')

@app.route('/create_dump', methods=['POST'])
@login_required
def create_dump():
    sse_messages.clear()
    threading.Thread(target=create_memory_dump).start()
    # for point 4
    with open('dump_origin.txt', 'w') as f:
        f.write('Generated by MemScan')

    
    return '', 204

@app.route('/run_plugins', methods=['POST'])
@login_required
def run_plugins():
    sse_messages.clear()
    threading.Thread(target=run_volatility_plugins).start()
    return '', 204

@app.route('/convert_plugins', methods=['POST'])
@login_required
def convert_plugins():
    sse_messages.clear()
    threading.Thread(target=convert_txt_to_csv).start()
    return '', 204



@app.route('/upload_dump', methods=['POST'])
@login_required
def upload_dump():
    if 'dumpfile' not in request.files:
        return '❌ No file uploaded', 400
    file = request.files['dumpfile']
    if file.filename == '':
        return '❌ No file selected', 400
    if file:
        file.save(MEMORY_DUMP_PATH)
        # i write this code for point 4
        # mark origin
        with open(DUMP_ORIGIN_PATH, 'w') as f:
            f.write('Uploaded by user')
            

        #return redirect('/')

        send_sse_message("📥 Memory dump uploaded and saved as 'memory_dump.dmp'")
        return '✅ File uploaded and renamed to memory_dump.dmp', 200

@app.route("/merge_csvs", methods=["POST"])
def merge_csvs():
    sse_messages.clear()
    def background_merge():
        try:
            send_sse_message("🔄 Merging plugin CSVs... please wait.")
            success, message = merge_plugin_csvs(log=send_sse_message)
            if success:
                send_sse_message("✅ Merging completed.")
            else:
                send_sse_message(f"❌ Merging failed: {message}")
        except Exception as e:
            send_sse_message(f"❌ Exception during merging: {str(e)}")
    threading.Thread(target=background_merge).start()
    return '', 204

@app.route("/predict_malware", methods=["POST"])
def predict_malware():
    sse_messages.clear()
    def background_prediction():
        try:
            send_sse_message("🚀 Starting prediction on merged features...")
            success, msg = run_prediction(log=send_sse_message)
            if success:
                send_sse_message("✅ Prediction complete.")
            else:
                send_sse_message(f"❌ Prediction failed: {msg}")
        except Exception as e:
            send_sse_message(f"🔥 Crash in prediction: {str(e)}")
    threading.Thread(target=background_prediction).start()
    return '', 204

@app.route("/chart_data", methods=["GET"])
def chart_data():
    try:
        file_path = os.path.join(BASE_DIR, "merged_csv_outputs", "predicted_output.csv")
        if not os.path.exists(file_path):
            return {"error": "Prediction file not found."}, 404
        df = pd.read_csv(file_path)
        binary_counts = df["Binary_Prediction"].value_counts().to_dict()
        category_counts = df["Malware_Type"].value_counts().to_dict()
        return {"binary": binary_counts, "category": category_counts}
    except Exception as e:
        return {"error": str(e)}, 500

# ✅ NEW: Single-click full analysis
@app.route('/start_analysis', methods=['POST'])
@login_required
def start_analysis():
    sse_messages.clear()
    def analysis_pipeline():
        try:
            send_sse_message("🚀 Starting full analysis pipeline...")
            #run_volatility_plugins()
            convert_txt_to_csv()
            success, message = merge_plugin_csvs(log=send_sse_message)
            if not success:
                send_sse_message(f"❌ Merging failed: {message}")
                return
            success, msg = run_prediction(log=send_sse_message)
            if not success:
                send_sse_message(f"❌ Prediction failed: {msg}")
                return
            send_sse_message("✅ Full analysis pipeline completed!")
        except Exception as e:
            send_sse_message(f"🔥 Pipeline crashed: {str(e)}")
    threading.Thread(target=analysis_pipeline).start()
    return '', 204

@app.route("/stream")
def stream():
    def event_stream(q):
        while True:
            result = q.get()
            yield f"data: {result}\n\n"
    q = queue.Queue()
    message_queues.append(q)
    return Response(event_stream(q), mimetype="text/event-stream")

if __name__ == '__main__':
    app.run(debug=True, threaded=True)
