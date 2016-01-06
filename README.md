### From Release Binary (Recommended)

* How to run

        $ ./incident-report  -c <cbserverurl> -a <api-token> -g <process-guid>

* Example

        $ ./incident-report  -c https://server.wedgie.org -a apitokengoeshere -g 00000001-0000-0900-01d1-37525da84f72

### From Source'
* Install all needed requirements:

        $ sudo pip install -r requirements.txt

* Run the script with specified parameters

        $ python incident_report.py -c <cbserverurl> -a <api-token> -g <process-guid>

A report will be generated in `./<process-guid>/index.html` for the specified process GUID

NOTE: REDIS is not required, but recommended if many reports are going to be generated

* To install REDIS on Centos 6 (source)

        $ wget http://download.redis.io/releases/redis-2.8.3.tar.gz
        $ tar xzvf redis-2.8.3.tar.gz
        $ cd redis-2.8.3
        $ make
        $ make install

* To install REDIS on Centos 6 (yum)

        $ rpm -Uvh http://download.fedoraproject.org/pub/epel/6/x86_64/epel-release-6-8.noarch.rpm
        $ rpm -Uvh http://rpms.famillecollet.com/enterprise/remi-release-6.rpm

        $ yum --enablerepo=remi,remi-test install redis

* Start REDIS

        $ service redis start

