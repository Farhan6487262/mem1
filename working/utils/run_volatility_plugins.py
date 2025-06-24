import subprocess
import os

#VOLATILITY_PATH = "D:/AIMODELSPROJECT/projects/sir sarfaraz fiver/working/vol4/volatility3/vol.py"
VOLATILITY_PATH = "D:/AIMODELSPROJECT/projects/sir sarfaraz fiver/frontendworking/volatility3/vol.py"
PLUGINS = [
    "windows.pslist",
    "windows.cmdline",
    "windows.psscan",
    "windows.pstree",
    "windows.dlllist",
    "windows.netscan",
    "windows.malfind",
    "windows.handles",
    "windows.ldrmodules",
    "windows.modules",
    "windows.suspicious_threads",
    "windows.hollowprocesses",
    "windows.callbacks",
    "windows.registry.hivelist"
]

OUTPUT_DIR = "plugin_outputs"
os.makedirs(OUTPUT_DIR, exist_ok=True)

def run_volatility_plugins(dump_path):
    results = {}
    for plugin in PLUGINS:
        try:
            output_file = os.path.join(OUTPUT_DIR, f"{plugin.replace('.', '_')}.txt")

            cmd = [
                "python", VOLATILITY_PATH,
                "-f", dump_path,
                plugin
            ]

            env = os.environ.copy()
            env["PYTHONIOENCODING"] = "utf-8"

            result = subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True, encoding="utf-8", errors="replace", env=env)

            with open(output_file, "w", encoding="utf-8") as f:
                f.write(result)

            results[plugin] = "✅ Completed"
        except subprocess.CalledProcessError as e:
            results[plugin] = f"❌ Error: {str(e.output)[:200]}"
        except Exception as ex:
            results[plugin] = f"⚠️ Exception: {str(ex)}"

    return results
