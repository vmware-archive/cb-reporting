* How to run

        $ ./incident-report  --guid <process-guid>

* Example

        $ ./incident-report  --guid <process-guid>

### From Source
* clone cb-reporting.git

        $ git clone https://github.com/carbonblack/cb-reporting.git

* Install all needed requirements:

        $ sudo pip install -r requirements.txt

* Run the script with specified parameters

        $ python incident_report.py --guid <process-guid>

A report will be generated in `./reports/<process-guid>/index.html` for the specified process GUID

## Support

1. Use the [Developer Community Forum](https://community.carbonblack.com/t5/Developer-Relations/bd-p/developer-relations) to discuss issues and ideas with other API developers in the Carbon Black Community.
2. Report bugs and change requests through the GitHub issue tracker. Click on the + sign menu on the upper right of the screen and select New issue. You can also go to the Issues menu across the top of the page and click on New issue.
3. View all API and integration offerings on the [Developer Network](https://developer.carbonblack.com/) along with reference documentation, video tutorials, and how-to guides.
