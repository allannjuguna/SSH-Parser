#! /usr/bin/python3
import streamlit as st
from funcs import *
import time
import pandas as pd

# Set page configuration
st.set_page_config(
    page_title="SSH Parser",
    page_icon="📊",
    layout="wide",
    initial_sidebar_state="expanded"
)


def br():
	st.write(" ")
	st.write(" ")


def parse_logs(logs):
	with st.spinner(text="Parsing logs"):
		successful_analytics=successful_logins(logs)
		password_spray_analytics=password_sprays(logs)
		bruteforce_analytics=bruteforce_attempts(logs)
		failed_negotiation_analytics=failed_sshkey_connections(logs)
		# time.sleep(5)
		st.toast(f"Successfully parsed logs")
	# st.success("Done")

	br()


	# summarize logs into %
	percentage=lambda a:f'{int(a/len(logs)*100)} %'


	st.markdown('### Summary')
	col1,col2,col3,col4=st.columns(4)

	col1.metric(" ",len(logs),"100%")
	col1.markdown("Total Logs")

	col2.metric(" ",len(successful_analytics),percentage(len(successful_analytics)))
	col2.markdown("Successful logins")

	col3.metric(" ",len(bruteforce_analytics),percentage(len(bruteforce_analytics)))
	col3.markdown("Bruteforce attempts")

	col4.metric(" ",len(password_spray_analytics),percentage(len(password_spray_analytics)))
	col4.markdown("Password Spray attempts")



	def generate_table(data,num_rows,config={}):
		table_data=pd.DataFrame(data[:num_rows])
		st.dataframe(table_data,column_config=config)

	br()
	st.markdown('### ✅ Successful Logons')
	num_rows = st.selectbox("Number of rows", [5,10,50,100, 500, 1000,10000],key="successful_analytics")
	# successful_analytics=[f'{i[:2] + "*"*2 + "." + "*"*2 + "." + i[-2:]}' for i in successful_analytics if i]
	generate_table(show_count(successful_analytics),num_rows)

	st.markdown('### 🔒 Last successful logins')
	data=last_successful_logins(logs)
	generate_table(data,5)

	br()
	st.markdown('### 🌐 Most active malicious IPs - Bruteforce')
	num_rows = st.selectbox("Number of rows", [5,10,50,100, 500, 1000,10000],key="malicious_ips")
	ips=[f"{(log.split(' : ')[1])}" for log in bruteforce_analytics]
	ip_array=show_count(ips) # Add appearance count to the ips
	# Add abuse IP references
	for item in ip_array:
		item["Abuse IP Link"]=f"https://www.abuseipdb.com/check/{item['Source']}"



	generate_table(ip_array,num_rows,config={"Abuse IP Link": st.column_config.LinkColumn()})

	st.markdown('#### Visual Representation')
	try:
		num_rows = st.selectbox("Number of rows", [10,50,100, 500, 1000,10000],key="visual_malicious_ips")
		data=show_count(ips)
		chart_data=pd.DataFrame(data[:num_rows]).set_index("Source")
		st.bar_chart(chart_data)
	except Exception as e:
		# st.toast(f'Error : {e}')
		st.warning("Empty data")



	br()
	st.markdown('### 👤 Most Targeted Accounts')
	num_rows = st.selectbox("Number of rows", [5,10,50,100, 500, 1000,10000],key="usernames")
	accounts=[f"{(log.split(' : ')[0])}" for log in bruteforce_analytics]
	generate_table(show_count(accounts),num_rows)

	st.markdown('#### Visual Representation')
	try:
		num_rows = st.selectbox("Number of rows", [10,50,100, 500, 1000,10000],key="visual_malicious_users")
		data=show_count(accounts)
		chart_data=pd.DataFrame(data[:num_rows]).set_index("Source")
		st.line_chart(chart_data)
	except Exception as e:
		# st.toast(f'Error : {e}')
		st.warning("Empty data")






	br()
	st.markdown('### 🚨 Password Spray Attempts')
	num_rows = st.selectbox("Number of rows", [5,10,50,100, 500, 1000,10000],key="password_spray_analytics")
	ip_array=show_count(password_spray_analytics)
	# Add abuse IP references
	for item in ip_array:
		item["Abuse IP Link"]=f"https://www.abuseipdb.com/check/{item['Source']}"
	generate_table(ip_array,num_rows,config={"Abuse IP Link": st.column_config.LinkColumn()})



	br()
	st.markdown('### 🛠️ Bruteforce Attempts per User')
	num_rows = st.selectbox("Number of rows", [5,10,50,100, 500, 1000,10000],key="bruteforce_analytics")
	ip_array=show_count(bruteforce_analytics)
	# Add abuse IP references
	for item in ip_array:
		item["Abuse IP Link"]=f"https://www.abuseipdb.com/check/{item['Source']}"
	generate_table(ip_array,num_rows,config={"Abuse IP Link": st.column_config.LinkColumn()})



	br()
	st.markdown('### ❌🔑 Failed SSH key negotiations')
	num_rows = st.selectbox("Number of rows", [5,10,50,100, 500, 1000,10000],key="failed_negotiation_analytics")
	generate_table(show_count(failed_negotiation_analytics),num_rows)



st.title("SSH Log Parser")
filenames=["./files/auth.log","/var/log/auth.log","./files/sample.log",]
with st.sidebar:
	st.write("📊 SSH Parser")
	if filename := st.text_input("Enter the path of SSH log file to add",key="filename"):
		filenames.append(filename)
		st.success(f'Added file {filename}. You can now select the file in the drop down menu')
	
	with st.expander("How to Use the Tool"):
		st.write("""
			1. Select a file from the predefined list of files in the dropdown menu
			2. If the file is not present, enter the path of the file to parse in the sidebar, then select the file from the dropdown menu
			""")

	with st.expander("FAQ"):
		st.write("""
			1. 'Password Spray Attempts' count is greater than 'Most active malicious IPs - Bruteforce' count?
			This is because the 'Most active malicious IPs - Bruteforce' analytics do not contain password spray attempts, only bruteforce.

			2. How is this tool useful?
			This tool supports both Blue and Red teams by providing regularly updated lists of malicious IP addresses for early threat detection and blocking, as well as generating potential usernames that can be used by penetration testers during fuzzing and penetration testing. 
			""")
	with st.expander("About"):
		st.write("The tool automatically parses a provided SSH log file to extract all login attempts, successful, failed, bruteforce, password sprays etc. ")

if filename := st.selectbox("Select file to parse. Default is /var/log/auth.log", filenames,key="filenames"):
	with st.spinner(text="Loading logs"):
		logs=load_file(filename)
		if len(logs) < 1:
			st.warning(f"No logs loaded. Check file '{filename}'")
		else:
			st.toast(f"Loaded {len(logs)} logs ")
			parse_logs(logs)





