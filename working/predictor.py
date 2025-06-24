import os
import socket
import platform
import datetime
import pandas as pd
import numpy as np
import joblib
import matplotlib.pyplot as plt
import os, platform, subprocess, psutil, getpass, time
import uuid


from reportlab.platypus import Spacer
from reportlab.lib.pagesizes import letter, landscape
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    Image as RLImage, KeepInFrame
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER
from reportlab.lib import colors

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

DUMP_ORIGIN_PATH = os.path.join(BASE_DIR, 'dump_origin.txt')

'''
# Read dump origin for point 4
dump_origin = "Unknown"
if os.path.exists('dump_origin.txt'):
    with open('dump_origin.txt') as f:
        dump_origin = f.read().strip()

#with open(DUMP_ORIGIN_PATH) as f:
 #   dump_origin = f.read().strip()
   '''
        

def run_prediction(
    input_csv="merged_csv_outputs/test.csv",
    model_dir="trainedmodels",
    output_csv="merged_csv_outputs/predicted_output.csv",
    log=None
):
    try:
        if log: log("🧠 Loading models and label encoder...")

        rf_binary = joblib.load(os.path.join(model_dir, "rf_binary_model.pkl"))
        rf_category = joblib.load(os.path.join(model_dir, "rf_category_model.pkl"))
        label_encoder = joblib.load(os.path.join(model_dir, "rf_label_encoder.pkl"))
        features = joblib.load(os.path.join(model_dir, "feature_names.pkl"))

        if log: log("📄 Reading merged_features.csv...")

        full_data = pd.read_csv(input_csv, low_memory=True)
        X_new = full_data[features]

        for col in features:
            X_new[col] = pd.to_numeric(X_new[col], errors='coerce').fillna(0).astype(np.float32)

        if log: log("🔍 Predicting binary malware status...")
        binary_predictions = rf_binary.predict(X_new)
        binary_probs = rf_binary.predict_proba(X_new)

        if log: log("🔬 Predicting malware category...")
        category_predictions = rf_category.predict(X_new)
        decoded_categories = label_encoder.inverse_transform(category_predictions)

        final_binary_prediction = ['Malware' if c != 'Benign' else 'Benign' for c in decoded_categories]

        if log: log("💾 Saving predictions to output CSV...")

        output = pd.DataFrame({
            'PID': full_data['PID'],
            'PPID': full_data.get('PPID', 0),
            'Process': full_data.get('Process', pd.Series(['N/A'] * len(full_data))),
            'CreateTime': full_data.get('CreateTime', pd.Series(['N/A'] * len(full_data))),
            'EndTime': full_data.get('EndTime', pd.Series(['N/A'] * len(full_data))),
            'Args': full_data.get('Args', pd.Series(['N/A'] * len(full_data))),
            'Threads': full_data.get('Threads', 0),
            'malfind': full_data.get('malfind_count', 0),
            'dll': full_data.get('dll_count', 0),
            'handle': full_data.get('handle_count', 0),
            'psscan': full_data.get('psscan_count', 0),
            'cmdline': full_data.get('cmdline_count', 0),
            'netscan': full_data.get('netscan_count', 0),
            'suspicious_threads': full_data.get('suspicious_threads_count', 0),
            'Binary_Prediction': final_binary_prediction,
            'Benign_Probability': binary_probs[:, 0],
            'Malware_Probability': binary_probs[:, 1],
            'Malware_Type': decoded_categories
        })

        output.to_csv(output_csv, index=False)

        counts = output['Binary_Prediction'].value_counts()
        plt.figure()
        counts.plot(kind='pie', autopct='%1.1f%%', colors=['green', 'red'], labels=['Benign', 'Malware'])
        pie_chart_path = output_csv.replace(".csv", "_binary_pie.png")
        #plt.title('Binary Classification')
        plt.title('Binary Classification', fontsize=20)
        
        #plt.xlabel('Class', fontsize=14)
        plt.ylabel('', fontsize=14)
        
        plt.ylabel('')
        plt.savefig(pie_chart_path)
        plt.close()

        plt.figure()
        output['Malware_Type'].value_counts().plot(kind='bar', color='blue')
        bar_chart_path = output_csv.replace(".csv", "_category_bar.png")
        plt.title('Malware Categories', fontsize=20)
        plt.xlabel('Category', fontsize= 14)
        plt.ylabel('Count', fontsize=14)
        
        plt.tight_layout()
        plt.savefig(bar_chart_path)
        plt.close()

        hostname = socket.gethostname()
        try:
            ip_address = socket.gethostbyname(hostname)
        except:
            ip_address = " dummy 127.0.0.1"


        os_name = platform.platform()
        os_profile = "Win10x64"
        kernel_dtb = "0x1aa000"

        total_processes = len(output)
        suspicious_count = output[output["Binary_Prediction"] == "Malware"].shape[0]
        high_risk_probability = int((suspicious_count / total_processes) * 100) if total_processes > 0 else 0

        running_processes = output[output["Binary_Prediction"] == "Malware"]
        
        top_proc_names = running_processes["Malware_Type"].head(3).tolist() if "Malware_Type" in running_processes.columns else []
        
        if not top_proc_names:
            top_proc_names = running_processes["PID"].astype(str).head(3).tolist()
        running_proc_info = " • " + ", ".join(top_proc_names)
        
        


        # ✅ to Get enhanced system info:
        hostname = os.environ.get('COMPUTERNAME', socket.gethostname())
        username = f"{hostname}\\{getpass.getuser()}"
        timezone = time.tzname[0]
        ram_gb = round(psutil.virtual_memory().total / (1024 ** 3), 2)
        try:
            model = subprocess.check_output('wmic computersystem get model', shell=True).decode().split('\\n')[1].strip()
        except:
            model = "N/A"
        system_type = f"x64-based PC" if platform.architecture()[0] == '64bit' else 'x86-based PC'

        
        mac_address = ':'.join(['{:02x}'.format((uuid.getnode() >> ele) & 0xff)
                            for ele in range(0,8*6,8)][::-1]).upper()
        #print(mac_address)
        timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        '''footer = Paragraph(f"Generated: {timestamp} — Memory Forensics & Malware Detection Report", normal_style)
        elements.append(Spacer(1, 1))
        elements.append(footer)'''
        
   
        # Read the dump origin:
        
        dump_origin = "Unknown"
        if os.path.exists(DUMP_ORIGIN_PATH):
            with open(DUMP_ORIGIN_PATH) as f:
                dump_origin = f.read().strip()

        
        
      
        
        
        
        

        create_summary_report(
            pdf_filename=output_csv.replace(".csv", "_summary_report.pdf"),
            #DUMP_ORIGIN_PATH = DUMP_ORIGIN_PATH,
            dump_origin=dump_origin,
            hostname=hostname,
            username=username,
            timezone=timezone,
            ram_gb=ram_gb,
            mac_address=mac_address,
            model=model,
            timestamp = timestamp,
            system_type=system_type,
            ip_address=ip_address,
            os_name=os_name,
            os_profile=os_profile,
            kernel_dtb=kernel_dtb,
            total_processes=total_processes,
            suspicious_count=suspicious_count,
            min_confidence=high_risk_probability,
            max_confidence=high_risk_probability,
            suspicious_df=output[output["Binary_Prediction"] == "Malware"].head(5),
            pie_chart_path=pie_chart_path,
            bar_chart_path=bar_chart_path,
            running_proc_info=running_proc_info
        )


        if log: log(f"✅ Prediction complete. Output saved to: {output_csv}")
        return True, "Prediction successful"

    except Exception as e:
        if log: log(f"❌ Error during prediction: {e}")
        return False, str(e)


def create_summary_report(
    pdf_filename,
    dump_origin,
    #DUMP_ORIGIN_PATH,
    hostname,
    username,
    timezone,
    ram_gb,
    mac_address,
    model,
    timestamp,
    system_type,
    ip_address,
    os_name,
    os_profile,
    kernel_dtb,
    total_processes,
    suspicious_count,
    min_confidence,
    max_confidence,
    suspicious_df,
    pie_chart_path,
    bar_chart_path,
    running_proc_info=" • svchost.exe, csrss.exe, wininit.exe"
):
    
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(name="Title", parent=styles['Title'], alignment=TA_CENTER, fontSize=34, textColor=colors.HexColor("#003366"))
    subtitle_style = ParagraphStyle(name="Subtitle", parent=styles['Title'], alignment=TA_CENTER, fontSize=24)
    heading_style = ParagraphStyle(name="Heading", parent=styles['Heading2'], fontSize=18, textColor=colors.HexColor("#003366"))
    normal_style = ParagraphStyle(name="Normal", parent=styles['Normal'], fontSize=12, leading=14)

    elements = []
    elements.append(Paragraph("MemScan", title_style))
    elements.append(Spacer(1, 30))
    elements.append(Paragraph("Memory Forensics & Malware Detection Report", subtitle_style))
    elements.append(Spacer(1, 20))

    left_col = []
    left_col.append(Paragraph("<b>Device Details</b>", heading_style))
    
    
    left_col.append(Paragraph(f"Dump Origin:{dump_origin}<br/>", normal_style))
    
    
    
    
    left_col.append(Paragraph(f"{hostname}<br/>", normal_style))
    #client donot want to see the ip address
    #left_col.append(Paragraph(f"{hostname}<br/>{ip_address}", normal_style))
    # entering new values
    left_col.append(Paragraph(f"{username}<br/>Time Zone: {timezone}<br/>RAM: {ram_gb} GB<br/>", normal_style))
    
    left_col.append(Paragraph(f"Mac Address: {mac_address} <br/>", normal_style))
    left_col.append(Paragraph(f"Report Generarated : {timestamp} <br/>", normal_style))
    
    
    left_col.append(Spacer(1, 5))

    
    left_col.append(Paragraph("<b>Running Processes Info</b>", heading_style))
    
    #left_col.append(Paragraph("<b>Top Running Processes</b>",{running_proc_info}, normal_style))
    left_col.append(Paragraph(f"<b>Top Running Processes:INFO:</b>{running_proc_info} <br/>", normal_style))
    # new code for malware category
    # Clean & split
    left_col.append(Spacer(1, 5))

    left_col.append(Paragraph("<b>Processes Information</b>", heading_style))
    left_col.append(Paragraph(
        """
        <b></b><br/>
        <b>Trojan:</b><br/>
        •A Trojan disguises itself as legitimate software to gain unauthorized access.<br/>
        •It may open backdoors, disable security measures, or download more malware.<br/>
        •Possible effects: Unauthorized remote access, credential theft, system instability.<br/>
        <b></b><br/>
        <b>Ransomware:</b><br/>
        •Ransomware encrypts files and demands payment for decryption. It can lock critical files and spread through networks.<br/>
        •Possible effects: Data loss, operational downtime, financial loss, ransom note displayed.<br/>
        <b></b><br/>
        <b>Spyware:</b><br/>
        •Spyware secretly monitors activity, captures credentials, and sends information to an attacker.<br/>
        •Possible effects: Privacy invasion, stolen passwords, degraded performance.<br/>
        <b></b><br/>
         <b>Bengin:</b><br/>
        •In cybersecurity and malware forensics, Benign means harmless or non-malicious.<br/>
        •A benign process or file does not pose any threat to the system.<br/>
        it is a normal, safe part of the operating system or legitimate software. 
        """,
        normal_style
    ))

    
    # now i move summary of analysis to the right column for a better pdf format
    #• svchost.exe, csrss.exe, wininit.exe<br/>
            

    #• High memory usage observed/>
    #• Run full malware scan<br/>
    #• Consider resetting Window ues credenfilals<br/>
    #• Avoid accessing unknow network shares before cleanup
    #• Upload full disk image if system was in production
    
    
    

    right_col = []

# for operating system info in right column of report
    right_col.append(Paragraph("<b>Operating System Info</b>", heading_style))
    #left_col.append(Paragraph(f"{os_name}<br/>OS Profile: {os_profile}<br/>Kernel DTB: {kernel_dtb}", normal_style))
    right_col.append(Paragraph(f"{os_name}<br/>System Model: {model}<br/>System Type: {system_type}<br/>OS: {os_name}<br/>OS Profile: {os_profile}<br/>Kernel DTB: {kernel_dtb}", normal_style))
    right_col.append(Spacer(1, 5))

# for summarry of analysis

    # Determine risk zone based on min_confidence
    if min_confidence >= 80:
        risk_zone = "Red Zone → Highly Dangerous"
        risk_color = "red"
    elif 30 <= min_confidence < 80:
        risk_zone = "Yellow Zone → Moderately Dangerous"
        risk_color = "orange"
    else:
        risk_zone = "Green Zone → Low Threat"
        risk_color = "green"
        
    # here trying to put the framework tools her 
    right_col.append(Paragraph("<b>Framework & Tools Used</b>", heading_style))
    
        
        # following lines are not to be included in frame work & tools used information so excluded
        #✓ Frontend: ReactJS + Tailwind CSS<br/>
        #✓ Backend: Node.js + Express + MongoDB<br/>
        #✓ AI Model: RandomForestClassifier<br/>
    
    right_col.append(Paragraph(
        """
        ✓ Memory Forensics: Volatility 3<br/>
        ✓ Feature Engineering: Pandas, joblib<br/>
        ✓ File Format: memory_dump.dmp
        """,
        normal_style
    ))
    right_col.append(Spacer(1, 5))
       
    
    right_col.append(Paragraph("<b>Summary of Analysis</b>", heading_style))
    right_col.append(Paragraph(
        f"""
        • Total processes analyzed: {total_processes}<br/>
        • Suspicious processes: {suspicious_count}<br/>
        • High-risk probability: {min_confidence}%<br/>
        • Level Risk-Zone: {risk_zone}<br/>
        • Risk Zone: <font color="{risk_color}">{risk_zone}</font><br/>
        • AI/ML powered detection
        """,
        normal_style
    ))
    
    right_col.append(Spacer(1, 5))






    pie = RLImage(pie_chart_path, width=160, height=120)
    
#    right_col.append(Spacer(1, 3))
    
    bar = RLImage(bar_chart_path, width=400, height=350)
    
    
    # for printing both chart side by side 
    '''charts = Table([[pie]], colWidths=[160, 160])
   
    charts.setStyle(TableStyle([
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE')
    ]))
    right_col.append(charts)
    right_col.append(Spacer(1, 1))'''

    charts = Table([[bar]], colWidths=[160, 160])

   
   
    charts.setStyle(TableStyle([
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE')
    ]))
   
   
   
   
    right_col.append(charts)
  
    
    right_col.append(Spacer(1, 5))

    # Create KeepInFrame wrappers
    left_frame = KeepInFrame(250, 400, left_col)   # reduced from 260
    right_frame = KeepInFrame(250, 400, right_col) # reduced from 260

    # Create a spacer column using an empty string or Spacer
    spacer = Spacer(150, 0)  # 20-points wide gap

    # Build table with 3 columns: left, spacer, right
    columns = Table([[left_frame, '', right_frame]], colWidths=[250, 150, 250])

    # Apply table style
    columns.setStyle(TableStyle([
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('LEFTPADDING', (0, 0), (-1, -1), 5),
        ('RIGHTPADDING', (0, 0), (-1, -1), 5),
    ]))

    # Add to document
    elements.append(columns)
    
    elements.append(Spacer(1, 30))

    if suspicious_df is not None:
        elements.append(Paragraph("<b>Process Analysis Table</b>", heading_style))

        suspicious_df = suspicious_df.copy().head(5)
        # change head 5 to 3 for reduce rows in the table 

        if 'Args' in suspicious_df.columns:
            suspicious_df['Args'] = suspicious_df['Args'].apply(
                lambda x: str(x)[:50] + '...' if len(str(x)) > 50 else str(x)
            )

        suspicious_df.insert(0, 'S.No', range(1, len(suspicious_df)+1))

        table_data = [suspicious_df.columns.tolist()]
        for _, row in suspicious_df.iterrows():
            row_list = []
            for col in suspicious_df.columns:
                val = row[col]
                if col == 'Args':
                    val = Paragraph(str(val), normal_style)
                else:
                    val = str(val)
                row_list.append(val)
            table_data.append(row_list)

        table = Table(
            table_data,
            hAlign='CENTER'
        )
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#003366")),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('GRID', (0, 0), (-1, -1), 0.25, colors.grey),
            ('FONTSIZE', (0, 0), (-1, -1), 6),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ]))
        elements.append(table)
        elements.append(Spacer(1, 5))
        
    
    disclaimer = Paragraph(
        "⚠️ <b>Note:</b> showing only some record, for further details check the predicted_output_summary_report.pdf ",
        

        
        ParagraphStyle(name="Disclaimer", parent=normal_style, fontSize=12, backColor=colors.pink)
    )
    elements.append(disclaimer)
    

    elements.append(Paragraph("⚠️ <b>Recommendation</b>", heading_style))


    elements.append(Paragraph(
        """
        • Investigate all high-risk processes immediately. &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; 
        • Block suspicious outbound network connections.<br/>
        • Perform a full disk malware scan. &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; 
        • Update and run anti-malware tools.<br/>
        • Reset system credentials if compromise is confirmed. &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; 
        • Avoid untrusted network shares until cleanup.<br/>
        • Consider submitting a full disk image for deeper analysis        
        """,
        normal_style
    ))
    elements.append(Spacer(1, 5))


    # update the disclaimer here 
    disclaimer = Paragraph(
        "⚠️ <b>Disclaimer:</b>This report is auto-generated and may contain errors. Always verify results with trusted tools and security professionals. The developers are not responsible for any consequences arising from its use.",
        ParagraphStyle(name="Disclaimer", parent=normal_style, fontSize=12, backColor=colors.pink)
    )
    elements.append(disclaimer)










    timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    footer = Paragraph(f"Generated: {timestamp} — Memory Forensics & Malware Detection Report", normal_style)
    elements.append(Spacer(1, 5))
    elements.append(footer)






    doc = SimpleDocTemplate(
        pdf_filename,
        pagesize=landscape(letter),
        rightMargin=5, leftMargin=5, topMargin=25, bottomMargin=25,
        allowSplitting=0
    )
    doc.build(elements)



    print(f"✅ One-page summary report created: {pdf_filename}")


