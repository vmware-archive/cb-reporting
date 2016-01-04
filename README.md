* install all needed requirements:

        sudo pip install requirements.txt

* run the script with specified parameters

        python incident_report.py -c <cbserverurl> -a <api-token> -g <process-guid>

A report will be generated in `./<process-guid>/index.html` for the specified process GUID

NOTE: redis-server is not required, but recommended if many reports are going to be generated
