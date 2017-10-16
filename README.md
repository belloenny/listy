# Ubuntu Server Setup
## Details
IP: 18.221.235.59
URL: http://18.221.235.59
SSH PORT: 2200

## Software Installed
apache2
python-dev
mod_wsgi
pip
python3
psycopg2
postgresql
git
flask


## 3rd party resources
https://www.codementor.io/devops/tutorial/getting-started-postgresql-server-mac-osx
https://www.digitalocean.com/community/tutorials/how-to-deploy-a-flask-application-on-an-ubuntu-vps
https://askubuntu.com/questions/138423/how-do-i-change-my-timezone-to-utc-gmt

## Configurations made
- Update/Upgrade (sudo apt-get update/upgrade)
- Created grader user (sudo adduser grader)
- Gave grader sudo privileges (sudo cp /etc/sudoers.d/90-cloud-init-users /etc/sudoers.d/grader) then (sudo nano /etc/sudoers.d/grader) changed name in file from 'ubuntu' to 'grader'
- Added 2200 port in Network settings on Lightsail instance
- Edited the sshd_config file (sudo nano /etc/ssh/sshd_config) and added port 2200 and restarted ssh services (sudo service ssh restart)
- Created ssh key locally (ssh-keygen) and copied the public key
- Logged in as grader and created .ssh folder (sudo mkdir .ssh)
- Pasted key in authorized_keys (sudo nano .ssh/authorized_keys)
- Changed folder permissions (sudo chmod 700 .ssh) and (sudo chmod 644 .ssh/authorized_keys)
- Changed the owner of the folder to grader (sudo chown .ssh grader:grader)
- Added Firewall rules and enabled it (sudo ufw allow 2200 -> sudo ufw allow www -> sudo ufw allow 123 -> sudo ufw enable)
- Changed timezone to UTC (sudo dpkg-reconfigure tzdata) scroll to none of the above and then to UTC
- Installed apache2 (sudo apt-get install apache2)
- Installed mod_wsgi (sudo apt-get install libapache2-mod-wsgi-py3)
- Enabled mod_wsgi (sudo a2enmod wsgi)
- Followed DigitalOcean instructions for deploying a FlaskApp (link above)
- Installed postgresql (sudo apt-get install postgresql)
- Logged into default PSQL user and ran psql (sudo su - postgres) then (psql)
- Created role catalog and password (CREATE ROLE catalog WITH LOGIN PASSWORD 'password';)
- Created my database (CREATE DATABASE listings;)
- Granted permissions to catalog for the DB (GRANT ALL PRIVILEGES ON DATABASE listing TO catalog;)
- Exited PSQL (/q)
- Installed git (sudo apt-get install git)
- CDed to /var/www/FlaskApp (folder created during digital ocean instructions)
- Cloned my app from github (git clone https://github.com/johnnyhperkins/listy.git)
- Renamed the folder to FlaskApp to function with the settings in flaskapp.wsgi per the digital ocean walkthrough (sudo mv listy FlaskApp)


# Listy App
This app is a rudimentary version of craigslist that allows users to create accounts using different OAuth providers or by entering a username, email and password. Users who've created their own accounts have the ability to update their profile username, password, email and photo. Users can create listings which are displayed in order of their creation date on the homepage. Users can filter listings by categories. 

# Running the app
To run the app, install Vagrant and VirtualBox, clone the fullstack-nanodegree-vm, clone this project's folder into the VM's folder, launch Vagrant, cd into the catalog folder, and run the application.py file. Access the site locally by visiting http://localhost:8000