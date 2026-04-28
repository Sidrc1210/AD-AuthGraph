# AD-AuthGraph

A pipeline of PowerShell and Python scripts which map authorization in an Active Directory environment.
Active Directory, developed by Microsoft, is the most widely used directory service which manages users, computers, and security permissions within a network, from a central database.
Within an Active Directory environment, authorization is a critical function after authentication (verifying identity). Authorization determines what kind of access and permissions users have over the resources (files, applications, servers etc.) in a network. This not only impacts hierarchy but also security in an Active Directory domain.
AD AuthGraph maps authorization in a domain, primarily ACLs (Access Control Lists) and their security implications.

As mentioned already it is a pipeline of scripts which executes in the given order:

i)	Collect-ADAuthorizationState.ps1 - A PowerShell script collects the raw Active Directory data and stores it in JSON file ad_authorization_state.json.

ii)	graph_builder.py - Uses data stored in the JSON file ad_authorization_state.json to build a directed graph with nodes and edges. Where nodes are users, groups, and computers. Edges are the relationships that develop between the nodes as a result of the application of authorization in the domain. The created graph is stored in the JSON file ad_authorization_state_graph.json.


iii)	analyzer.py – Consumes the data from ad_authorization_state_graph.json to determine the authorization flow in the domain. This script determines how the current permissions impact the security state of the domain. The output is stored in the ad_authorization_state_analyzed.json.

iv)	refiner.py – Consumes data from the output of analyzer.py that is ad_authorization_state_analyzed.json to refine the analysis. Its main purpose is to reduce the signal-to-noise ratio. Even a small Active Directory network can throw up multiple paths and privileges. This script maps ACL paths and the OUs connected to them. 

v)	visualizer.py – This is the final script in the pipeline which consumes the data from ad_authorization_state_refined.json (output of refiner.py) to generate an HTML report. The report includes a visual graph explorer, lists the ACL Abuse Chains, Domain Admin Privilege Paths, Kerberoastable Identities.

vi)	main.py – This is the execution script. The PowerShell script Collect-ADAuthorizationState.ps1 has collected and stored data, main.py executes the entire pipeline graph_builder.py -> analyzer.py -> refiner.py -> visualizer.py with a single terminal command: 
		
		python main.py ad_authorization_state.json

How to use AD-AuthGraph?
1.	AD-AuthGraph has to be run from Domain Controller (DC) machine of the current Domain.
2.	User should have requisite privileges to run scripts on the DC.
3.	Download by cloning the repository or you can also directly download the scripts.
4.	Make sure to save all the scripts in a single directory.
5.	You will need to be on a PowerShell terminal to run AD-AuthGraph.
6.	 AD-AuthGraph is built to run as a pipeline.
   
		(i)	Compulsory to run Collect-ADAuthorizationState.ps1 first. Output file ad_authorization_state.json

  	  		     .\Collect-ADAuthorizationState.ps1
	
		(ii)	Execute all the Python scripts in order graph_builder.py -> analyzer.py -> refiner.py -> visualizer.py with a single terminal command

  	              python main.py ad_authorization_state.json

  	                    
	
		(iii)	You can also run the Python scripts individually with output JSON file of the previous script in the pipeline as the parameter, using the following terminal commands:

  	           python graph_builder.py ad_authorization_state.json
  	 
               python analyzer.py ad_authorization_state_graph.json
  	 
			   python refiner.py ad_authorization_state_analyzed.json
  	 
			   python visualizer.py ad_authorization_state_refined.json
          
Note: Refer to the PDF Project Report (github path) to see screenshots of the expected terminal responses.

AD-AuthGraph has been conceptualized as a learning project to understand IAM (Identity and Access Management). Authentication and Authorization are both critical components of security strategy. This project is an attempt to understand the second more in-depth. How authorization flows and how even a single change in permission impacts the security posture of the entire network.

What does this repository contain?

- Complete-pipeline : The entire AD-AuthGraph pipeline:
		i)	Collect-ADAuthorizationState.ps1
		ii)	graph_builder.py
		iii) analyzer.py
		iv)	refiner.py
		v)	visualizer.py
		vi)	main.py 

-	domain_blues_local_test_states - Consists of the Output JSON files, screenshots, HTML reports, with READMEs; all generated with multiple executions of AD-AuthGraph in my personal Active Directory Lab. The HTML reports of all the test states can be viewed by navigating to the following links:

        state 0: https://sidrc1210.github.io/AD-AuthGraph/domain_blues_local_test_states/state0_baseline/ad_authorization_state0_report.html
 	    state 1: https://sidrc1210.github.io/AD-AuthGraph/domain_blues_local_test_states/state1_privileges_applied/ad_authorization_state_report.html
 	    state 2: https://sidrc1210.github.io/AD-AuthGraph/domain_blues_local_test_states/State2_ResetPassword/ad_authorization_state_report_refined.html
 	    state 3: https://sidrc1210.github.io/AD-AuthGraph/domain_blues_local_test_states/State3_WriteDACL/ad_authorization_state_report_refined.html
 	    state 4: https://sidrc1210.github.io/AD-AuthGraph/domain_blues_local_test_states/State4_ResetPassword2/ad_authorization_state_report_refined.html
 	    state 5: https://sidrc1210.github.io/AD-AuthGraph/domain_blues_local_test_states/State5_WriteProperty/ad_authorization_state_report_refined.html
 	Documents of every state tested are collected in relevantly named folders. These HTML report link of the state will also be in its README.
 	    Note: Folder names are case-sensitive; use links as provided.

-	Script Explainers - The Project also served as a personal learning endeavor for scripting with PowerShell and Python. Although, I have used LLMs (free-tier) to develop the code; I have personally studied and tried to explain underlying logic of the scripts. These script explainers I believe can be useful for anyone who wants to learn Python or PowerShell code along with Active Directory and IAM security concepts.

-	Project Report – PDF file which serves as a guide for AD AuthGraph user. Mainly, an organized collection of project notes and screenshots.

-	License - GNU General Public License (GPLv3)  	

AD-AuthGraph has been an immersive experience for me personally and I look forward to all feedback from the community.   


