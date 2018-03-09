# Fail 2 ban for windows firewall

## What is this

This is a C# tool that allows the system to automatically set firewall rules based on fail2ban dummy file. It also supports plugins for further development.

## How does it work

This tool reads the fail2ban.dummy(default, you can modify it in dummy.action), then monitor the dummy file and use windows firewall to add the blocks.

## How to use

    1. You need to modify the original fail2ban configurations:
```
    cd /etc/fail2ban/action.d/
    cp dummy.conf dummy-wsl.conf  #this cannot be changed
```
    2. Then you need to edit the dummy-wsl file. Changing all the /var/run into /tmp or anywhere else that is not a tmpfs directory.
```
    vi dummy-wsl.conf
    :%s/\/var\/run/[your desired directory]/g
    (e.g. :%s/\/var\/run/\/tmp/g)
    (Be aware you have to escape the slashes.)
    Then, use :wq to write the config file.
    If you encountered any error or mis-operation, use :q! to quit the vi and restart step 2 again.
```
    
    3. You need to manually create the directory you specified in the step 1
```
    mkdir /tmp/fail2ban
```
    4. You need to edit the action for the fail2ban jails. 
       You may use jail.conf / jail.local to set the default action to dummy-wsl, 
       you can also add a "action = dummy-wsl" to each jail section you enabled or configured under jail.d.
       
       Here's an example:
```
[sshd]
enabled = true
bantime = 1200
maxretry = 3
action = dummy-wsl
```
    5. You will need to use InstallUtil.exe to install the service. The service runs as LocalSystem account so you have to install it using an administrator account.
    6. You can check IPluginAPIs and PluginDemo to start your own plugin. Please put the plugins under the "Plugins" folder.
    
This program is published under GNU General Public License v3.0.
