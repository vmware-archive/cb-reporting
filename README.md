* How to run

        $ ./incident-report  --guid <process-guid>

* Example

        $ ./incident-report  --guid <process-guid>

### From Source'
* clone cb-reporting.git

        $ git clone https://github.com/carbonblack/cb-reporting.git
        $ git checkout zach-dev

* Install all needed requirements:

        $ sudo pip install -r requirements.txt

* Run the script with specified parameters

        $ python incident_report.py -g <process-guid>

A report will be generated in `./reports/<process-guid>/index.html` for the specified process GUID

