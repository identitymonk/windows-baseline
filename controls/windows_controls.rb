# encoding: utf-8

# copyright: 2019, Patrick Muench / Torsten Loebner

control 'windows-001' do
  title 'Ensure \'Enforce password history\' is set to \'24 or more password(s)\''
  desc 'This policy setting determines the number of renewed, unique passwords that have to be associated with a user account before you can reuse an old password. The value for this policy setting must be between 0 and 24 passwords. The default value for Windows Vista is 0 passwords, but the default setting in a domain is 24 passwords. To maintain the effectiveness of this policy setting, use the Minimum password age setting to prevent users from repeatedly changing their password.

  The recommended state for this setting is: 24 or more password(s).'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '1.1.1'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '1.1.1'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M3', 'Sichere Administration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe security_policy do
    its('PasswordHistorySize') { should be >= attribute('password_history_size') }
  end
end

control 'windows-002' do
  title 'Ensure \'Maximum password age\' is set to \'60 or fewer days, but not 0\''
  desc 'This policy setting defines how long a user can use their password before it expires.

  Values for this policy setting range from 0 to 999 days. If you set the value to 0, the password will never expire.

  Because attackers can crack passwords, the more frequently you change the password the less opportunity an attacker has to use a cracked password. However, the lower this value is set, the higher the potential for an increase in calls to help desk support due to users having to change their password or forgetting which password is current.

  The recommended state for this setting is 60 or fewer days, but not 0.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '1.1.2'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '1.1.2'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M3', 'Sichere Administration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe security_policy do
    its('MaximumPasswordAge') { should be <= attribute('maximum_password_age') }
  end
  describe security_policy do
    its('MaximumPasswordAge') { should be > 0 }
  end
end

control 'windows-003' do
  title 'Ensure \'Minimum password age\' is set to \'1 or more day(s)\''
  desc 'This policy setting determines the number of days that you must use a password before you can change it. The range of values for this policy setting is between 1 and 999 days. (You may also set the value to 0 to allow immediate password changes.) The default value for this setting is 0 days.

  The recommended state for this setting is: 1 or more day(s).'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '1.1.3'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '1.1.3'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M3', 'Sichere Administration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe security_policy do
    its('MinimumPasswordAge') { should be >= 1 }
  end
end

control 'windows-004' do
  title 'Ensure \'Minimum password length\' is set to \'14 or more character(s)\''
  desc 'This policy setting determines the least number of characters that make up a password for a user account. There are many different theories about how to determine the best password length for an organization, but perhaps "pass phrase" is a better term than "password." In Microsoft Windows 2000 and newer, pass phrases can be quite long and can include spaces. Therefore, a phrase such as "I want to drink a $5 milkshake" is a valid pass phrase; it is a considerably stronger password than an 8 or 10 character string of random numbers and letters, and yet is easier to remember. Users must be educated about the proper selection and maintenance of passwords, especially with regard to password length. In enterprise environments, the ideal value for the Minimum password length setting is 14 characters, however you should adjust this value to meet your organization\'s business requirements.

  The recommended state for this setting is: 14 or more character(s). '
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '1.1.4'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '1.1.4'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M3', 'Sichere Administration'] # FIXME: check Baustein

  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe security_policy do
    its('MinimumPasswordLength') { should be >= 14 }
  end
end

control 'windows-005' do
  title 'Ensure \'Password must meet complexity requirements\' is set to \'Enabled\''
  desc 'This policy setting checks all new passwords to ensure that they meet basic requirements for strong passwords.
  When this policy is enabled, passwords must meet the following minimum requirements: -- Not contain the user\'s account name or parts of the user\'s full name that exceed two consecutive characters
  -- Be at least six characters in length
  -- Contain characters from three of the following four categories:
  ---- English uppercase characters (A through Z)
  ---- English lowercase characters (a through z)
  ---- Base 10 digits (0 through 9)
  ---- Non-alphabetic characters (for example, !, $, #, %)
  ---- A catch-all category of any Unicode character that does not fall under the previous four categories. This fifth category can be regionally specific.
  Each additional character in a password increases its complexity exponentially. For instance, a seven-character, all lower-case alphabetic password would have 267 (approximately 8 x 109 or 8 billion) possible combinations. At 1,000,000 attempts per second (a capability of many password-cracking utilities), it would only take 133 minutes to crack. A seven-character alphabetic password with case sensitivity has 527 combinations. A seven-character case-sensitive alphanumeric password without punctuation has 627 combinations. An eight-character password has 268 (or 2 x 1011) possible combinations. Although this might seem to be a large number, at 1,000,000 attempts per second it would take only 59 hours to try all possible passwords. Remember, these times will significantly increase for passwords that use ALT characters and other special keyboard characters such as "!" or "@". Proper use of the password settings can help make it difficult to mount a brute force attack.
  The recommended state for this setting is: Enabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '1.1.5'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '1.1.5'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M3', 'Sichere Administration']

  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe security_policy do
    its('PasswordComplexity') { should eq 1 }
  end
end

control 'windows-006' do
  title 'Ensure \'Store passwords using reversible encryption\' is set to \'Disabled\''
  desc 'This policy setting determines whether the operating system stores passwords in a way that uses reversible encryption, which provides support for application protocols that require knowledge of the user\'s password for authentication purposes. Passwords that are stored with reversible encryption are essentially the same as plaintext versions of the passwords.

  The recommended state for this setting is: Disabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '1.1.6'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '1.1.6'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M3', 'Sichere Administration']

  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe security_policy do
    its('ClearTextPassword') { should eq 0 }
  end
end

control 'windows-007' do
  title 'Ensure \'Account lockout duration\' is set to \'15 or more minute(s)\''
  desc 'This policy setting determines the length of time that must pass before a locked account is unlocked and a user can try to log on again. The setting does this by specifying the number of minutes a locked out account will remain unavailable. If the value for this policy setting is configured to 0, locked out accounts will remain locked out until an administrator manually unlocks them.

  Although it might seem like a good idea to configure the value for this policy setting to a high value, such a configuration will likely increase the number of calls that the help desk receives to unlock accounts locked by mistake. Users should be aware of the length of time a lock remains in place, so that they realize they only need to call the help desk if they have an extremely urgent need to regain access to their computer.

  The recommended state for this setting is: 15 or more minute(s).'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '1.2.1'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '1.2.1'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M3', 'Sichere Administration']

  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe security_policy do
    its('LockoutDuration') { should be >= 900 }
  end
end

control 'windows-008' do
  title 'Ensure \'Account lockout threshold\' is set to \'10 or fewer invalid logon attempt(s), but not 0\''
  desc 'This policy setting determines the number of failed logon attempts before the account is locked. Setting this policy to 0 does not conform to the benchmark as doing so disables the account lockout threshold.

  The recommended state for this setting is: 10 or fewer invalid logon attempt(s), but not 0.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '1.2.2'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '1.2.2'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M3', 'Sichere Administration'] # FIXME: check Baustein

  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe security_policy do
    its('LockoutBadCount') { should be <= 10 }
  end
  describe security_policy do
    its('LockoutBadCount') { should be > 0 }
  end
end

control 'windows-009' do
  title 'Ensure \'Reset account lockout counter after\' is set to \'15 or more minute(s)\''
  desc 'This policy setting determines the length of time before the Account lockout threshold resets to zero. The default value for this policy setting is Not Defined. If the Account lockout threshold is defined, this reset time must be less than or equal to the value for the Account lockout duration setting.
  If you leave this policy setting at its default value or configure the value to an interval that is too long, your environment could be vulnerable to a DoS attack. An attacker could maliciously perform a number of failed logon attempts on all users in the organization, which will lock out their accounts. If no policy were determined to reset the account lockout, it would be a manual task for administrators. Conversely, if a reasonable time value is configured for this policy setting, users would be locked out for a set period until all of the accounts are unlocked automatically.

  The recommended state for this setting is: 15 or more minute(s).'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '1.2.3'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '1.2.3'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M3', 'Sichere Administration'] # FIXME: check Baustein

  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe security_policy do
    its('ResetLockoutCount') { should be >= 900 }
  end
end

control 'windows-010' do
  title 'Ensure \'Access Credential Manager as a trusted caller\' is set to \'No One\''
  desc 'This security setting is used by Credential Manager during Backup and Restore. No accounts should have this user right, as it is only assigned to Winlogon. Users\' saved credentials might be compromised if this user right is assigned to other entities.

  The recommended state for this setting is: No One.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.2.1'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.2.1'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M3', 'Sichere Administration', 'SYS.1.2.2.M4', 'Sichere Konfiguration']

  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe security_policy do
    its('SeTrustedCredManAccessPrivilege') { should eq [] }
  end
end

control 'windows-011' do
  title 'Configure \'Access this computer from the network\''
  desc 'This policy setting allows other users on the network to connect to the computer and is required by various network protocols that include Server Message Block (SMB)-based protocols, NetBIOS, Common Internet File System (CIFS), and Component Object Model Plus (COM+).

  - Level 1 - Domain Controller. The recommended state for this setting is: Administrators, Authenticated Users, ENTERPRISE DOMAIN CONTROLLERS.
  - Level 1 - Member Server. The recommended state for this setting is: Administrators, Authenticated Users. '
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.2.2'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': ['2.2.2', '2.2.3']
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M3', 'Sichere Administration']

  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe security_policy do
    its('SeNetworkLogonRight') { should eq attribute('se_network_logon_right') }
  end
end

control 'windows-012' do
  title 'Ensure \'Act as part of the operating system\' is set to \'No One\''
  desc 'This policy setting allows a process to assume the identity of any user and thus gain access to the resources that the user is authorized to access.
  The recommended state for this setting is: No One.

  Note: This user right is considered a "sensitive privilege" for the purposes of auditing.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.2.3'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.2.4'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe security_policy do
    its('SeTcbPrivilege') { should eq ['S-1-0-0'] }
  end
end

control 'windows-013' do
  title 'Ensure \'Add workstations to domain\' is set to \'Administrators\''
  desc 'This policy setting specifies which users can add computer workstations to the domain. For this policy setting to take effect, it must be assigned to the user as part of the Default Domain Controller Policy for the domain. A user who has been assigned this right can add up to 10 workstations to the domain. Users who have been assigned the Create Computer Objects permission for an OU or the Computers container in Active Directory can add an unlimited number of computers to the domain, regardless of whether or not they have been assigned the Add workstations to domain user right.

  In Windows-based networks, the term security principal is defined as a user, group, or computer that is automatically assigned a security identifier to control access to resources. In an Active Directory domain, each computer account is a full security principal with the ability to authenticate and access domain resources. However, some organizations may want to limit the number of computers in an Active Directory environment so that they can consistently track, build, and manage the computers. If users are allowed to add computers to the domain, tracking and management efforts would be hampered. Also, users could perform activities that are more difficult to trace because of their ability to create additional unauthorized domain computers.

  The recommended state for this setting is: Administrators.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.2.4'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.2.5'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M3', 'Sichere Administration', 'SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe security_policy do
    its('SeMachineAccountPrivilege') { should eq ['S-1-5-32-544'] }
  end
end

control 'windows-014' do
  title 'Ensure \'Adjust memory quotas for a process\' is set to \'Administrators, LOCAL SERVICE, NETWORK SERVICE\''
  desc 'This policy setting allows a user to adjust the maximum amount of memory that is available to a process. The ability to adjust memory quotas is useful for system tuning, but it can be abused. In the wrong hands, it could be used to launch a denial of service (DoS) attack.

  The recommended state for this setting is: Administrators, LOCAL SERVICE, NETWORK SERVICE.

  Note: A Member Server that holds the Web Server (IIS) Role with Web Server Role Service will require a special exception to this recommendation, to allow IIS application pool(s) to be granted this user right.

  Note #2: A Member Server with Microsoft SQL Server installed will require a special exception to this recommendation for additional SQL-generated entries to be granted this user right.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.2.5'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.2.6'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe security_policy do
    its('SeIncreaseQuotaPrivilege') { should include 'S-1-5-19' }
    its('SeIncreaseQuotaPrivilege') { should include 'S-1-5-20' }
    its('SeIncreaseQuotaPrivilege') { should include 'S-1-5-32-544' }
  end
end

control 'windows-015' do
  title 'Ensure \'Allow log on locally\' is set to \'Administrators\''
  desc 'This policy setting determines which users can interactively log on to computers in your environment. Logons that are initiated by pressing the CTRL+ALT+DEL key sequence on the client computer keyboard require this user right. Users who attempt to log on through Terminal Services / Remote Desktop Services or IIS also require this user right.

  The Guest account is assigned this user right by default. Although this account is disabled by default, it is recommended that you enable this setting through Group Policy. However, this user right should generally be restricted to the Administrators and Users groups. Assign this user right to the Backup Operators group if your organization requires that they have this capability.

  The recommended state for this setting is: Administrators.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.2.6'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.2.7'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M3', 'Sichere Administration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe security_policy do
    its('SeInteractiveLogonRight') { should eq attribute('se_interactive_logon_right') }
  end
end

control 'windows-016' do
  title 'Configure \'Allow log on through Remote Desktop Services\''
  desc 'This policy setting determines which users or groups have the right to log on as a Remote Desktop Services client. If your organization uses Remote Assistance as part of its help desk strategy, create a group and assign it this user right through Group Policy. If the help desk in your organization does not use Remote Assistance, assign this user right only to the Administrators group or use the Restricted Groups feature to ensure that no user accounts are part of the Remote Desktop Users group.

  Restrict this user right to the Administrators group, and possibly the Remote Desktop Users group, to prevent unwanted users from gaining access to computers on your network by means of the Remote Assistance feature.
  - Level 1 - Domain Controller. The recommended state for this setting is: Administrators.
  - Level 1 - Member Server. The recommended state for this setting is: Administrators, Remote Desktop Users.

  Note: A Member Server that holds the Remote Desktop Services Role with Remote Desktop Connection Broker Role Service will require a special exception to this recommendation, to allow the Authenticated Users group to be granted this user right.

  Note #2: The above lists are to be treated as whitelists, which implies that the above principals need not be present for assessment of this recommendation to pass.

  Note #3: In all versions of Windows Server prior to Server 2008 R2, Remote Desktop Services was known as Terminal Services, so you should substitute the older term if comparing against an older OS.
  '
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.2.7'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': ['2.2.8', '2.2.9']
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M3', 'Sichere Administration']

  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe security_policy do
    its('SeRemoteInteractiveLogonRight') { should eq attribute('se_remote_interactive_logon_right') }
  end
end

control 'windows-017' do
  title 'Ensure \'Back up files and directories\' is set to \'Administrators\''
  desc 'This policy setting allows users to circumvent file and directory permissions to back up the system. This user right is enabled only when an application (such as NTBACKUP) attempts to access a file or directory through the NTFS file system backup application programming interface (API). Otherwise, the assigned file and directory permissions apply.

  The recommended state for this setting is: Administrators.

  Note: This user right is considered a "sensitive privilege" for the purposes of auditing.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.2.8'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.2.10'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M3', 'Sichere Administration', 'SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe security_policy do
    its('SeBackupPrivilege') { should eq attribute('se_backup_privilege') }
  end
end

control 'windows-018' do
  title 'Ensure \'Change the system time\' is set to \'Administrators, LOCAL SERVICE\''
  desc 'This policy setting determines which users and groups can change the time and date on the internal clock of the computers in your environment. Users who are assigned this user right can affect the appearance of event logs. When a computer\'s time setting is changed, logged events reflect the new time, not the actual time that the events occurred.

  The recommended state for this setting is: Administrators, LOCAL SERVICE.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.2.9'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.2.11'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M3', 'Sichere Administration', 'SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe security_policy do
    its('SeSystemtimePrivilege') { should eq attribute('se_systemtime_privilege') }
  end
end

control 'windows-019' do
  title 'Ensure \'Change the time zone\' is set to \'Administrators, LOCAL SERVICE\''
  desc 'This setting determines which users can change the time zone of the computer. This ability holds no great danger for the computer and may be useful for mobile workers.

  The recommended state for this setting is: Administrators, LOCAL SERVICE.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.2.10'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.2.12'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M3', 'Sichere Administration', 'SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe security_policy do
    its('SeSystemtimePrivilege') { should eq attribute('se_time_zone_privilege') }
  end
end

control 'windows-020' do
  title 'Ensure \'Create a pagefile\' is set to \'Administrators\''
  desc 'This policy setting allows users to change the size of the pagefile. By making the pagefile extremely large or extremely small, an attacker could easily affect the performance of a compromised computer.
  The recommended state for this setting is: Administrators.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.2.11'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.2.13'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe security_policy do
    its('SeCreatePagefilePrivilege') { should eq ['S-1-5-32-544'] }
  end
end

control 'windows-021' do
  title 'Ensure \'Create a token object\' is set to \'No One\''
  desc 'This policy setting allows a process to create an access token, which may provide elevated rights to access sensitive data.
  The recommended state for this setting is: No One.

  Note: This user right is considered a "sensitive privilege" for the purposes of auditing.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.2.12'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.2.14'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  describe security_policy do
    its('SeCreateTokenPrivilege') { should [] }
  end
end

control 'windows-022' do
  title 'Ensure \'Create global objects\' is set to \'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE\''
  desc 'This policy setting determines whether users can create global objects that are available to all sessions. Users can still create objects that are specific to their own session if they do not have this user right.

  Users who can create global objects could affect processes that run under other users\' sessions. This capability could lead to a variety of problems, such as application failure or data corruption.

  The recommended state for this setting is: Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE.

  Note: A Member Server with Microsoft SQL Server and its optional "Integration Services" component installed will require a special exception to this recommendation for additional SQL-generated entries to be granted this user right.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.2.13'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.2.15'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe security_policy do
    its('SeCreateGlobalPrivilege') { should eq ['S-1-5-19', 'S-1-5-20', 'S-1-5-32-544', 'S-1-5-6'] }
  end
end

control 'windows-023' do
  title 'Ensure \'Create permanent shared objects\' is set to \'No One\''
  desc 'This user right is useful to kernel-mode components that extend the object namespace. However, components that run in kernel mode have this user right inherently. Therefore, it is typically not necessary to specifically assign this user right.

  The recommended state for this setting is: No One.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.2.14'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.2.16'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe security_policy do
    its('SeCreatePermanentPrivilege') { should eq [] }
  end
end

control 'windows-024' do
  title 'Ensure \'Create symbolic links\' is set to \'Administrators\''
  desc 'This policy setting determines which users can create symbolic links. In Windows Vista, existing NTFS file system objects, such as files and folders, can be accessed by referring to a new kind of file system object called a symbolic link. A symbolic link is a pointer (much like a shortcut or .lnk file) to another file system object, which can be a file, folder, shortcut or another symbolic link. The difference between a shortcut and a symbolic link is that a shortcut only works from within the Windows shell. To other programs and applications, shortcuts are just another file, whereas with symbolic links, the concept of a shortcut is implemented as a feature of the NTFS file system.

  Symbolic links can potentially expose security vulnerabilities in applications that are not designed to use them. For this reason, the privilege for creating symbolic links should only be assigned to trusted users. By default, only Administrators can create symbolic links.

  - Level 1 - Domain Controller. The recommended state for this setting is: Administrators.
  - Level 1 - Member Server. The recommended state for this setting is: Administrators and (when the Hyper-V Role is installed) NT VIRTUAL MACHINE\Virtual Machines.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.2.15'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': ['2.2.17', '2.2.18']
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe security_policy do
    its('SeCreateSymbolicLinkPrivilege') { should eq attribute('se_create_symbolic_link_privilege') }
  end
end

control 'windows-025' do
  title 'Ensure \'Debug programs\' is set to \'Administrators\''
  desc 'This policy setting determines which user accounts will have the right to attach a debugger to any process or to the kernel, which provides complete access to sensitive and critical operating system components. Developers who are debugging their own applications do not need to be assigned this user right; however, developers who are debugging new system components will need it.

  The recommended state for this setting is: Administrators.

  Note: This user right is considered a "sensitive privilege" for the purposes of auditing.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.2.16'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.2.19'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe security_policy do
    its('SeDebugPrivilege') { should eq ['S-1-5-32-544'] }
  end
end

control 'windows-026' do
  title 'Ensure \'Deny access to this computer from the network\' is set to \'Guests\''
  desc 'This policy setting prohibits users from connecting to a computer from across the network, which would allow users to access and potentially modify data remotely. In high security environments, there should be no need for remote users to access data on a computer. Instead, file sharing should be accomplished through the use of network servers. This user right supersedes the Access this computer from the network user right if an account is subject to both policies.

  - Level 1 - Domain Controller. The recommended state for this setting is to include: Guests.
  - Level 1 - Member Server. The recommended state for this setting is to include: Guests, Local account and member of Administrators group.

  Caution: Configuring a standalone (non-domain-joined) server as described above may result in an inability to remotely administer the server.

  Note: The security identifier Local account and member of Administrators group is not available in Server 2008 R2 and Server 2012 (non-R2) unless MSKB 2871997 has been installed.

  Note #2: Configuring a Member Server or standalone server as described above may adversely affect applications that create a local service account and place it in the Administrators group - in which case you must either convert the application to use a domain-hosted service account, or remove Local account and member of Administrators group from this User Right Assignment. Using a domain-hosted service account is strongly preferred over making an exception to this rule, where possible.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.2.17'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': ['2.2.20', '2.2.21']
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M3', 'Sichere Administration', 'SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe security_policy do
    its('SeDenyNetworkLogonRight') { should eq attribute('se_deny_network_logon_right') }
  end
end

control 'windows-027' do
  title 'Ensure \'Deny log on as a batch job\' to include \'Guests\''
  desc 'This policy setting determines which accounts will not be able to log on to the computer as a batch job. A batch job is not a batch (.bat) file, but rather a batch-queue facility. Accounts that use the Task Scheduler to schedule jobs need this user right.

  This user right supersedes the Log on as a batch job user right, which could be used to allow accounts to schedule jobs that consume excessive system resources. Such an occurrence could cause a DoS condition. Failure to assign this user right to the recommended accounts can be a security risk.

  The recommended state for this setting is to include: Guests.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.2.18'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.2.22'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe security_policy do
    its('SeDenyServiceLogonRight') { should include 'S-1-5-32-546' }
  end
end

control 'windows-028' do
  title 'Ensure \'Deny log on as a service\' to include \'Guests\''
  desc 'This security setting determines which service accounts are prevented from registering a process as a service. This user right supersedes the Log on as a service user right if an account is subject to both policies.

  The recommended state for this setting is to include: Guests.

  Note: This security setting does not apply to the System, Local Service, or Network Service accounts.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.2.19'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.2.23'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe security_policy do
    its('SeDenyInteractiveLogonRight') { should include 'S-1-5-32-546' }
  end
end

control 'windows-029' do
  title 'Ensure \'Deny log on locally\' to include \'Guests\' (Scored)'
  desc 'This security setting determines which users are prevented from logging on at the computer. This policy setting supersedes the Allow log on locally policy setting if an account is subject to both policies.

  The recommended state for this setting is to include: Guests.

  Important: If you apply this security policy to the Everyone group, no one will be able to log on locally.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.2.20'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.2.24'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M3', 'Sichere Administration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe security_policy do
    its('SeDenyInteractiveLogonRight') { should include 'S-1-5-32-546' }
  end
end

control 'windows-030' do
  title 'Configure \'Deny log on through Remote Desktop Services\''
  desc 'This policy setting determines whether users can log on as Remote Desktop clients. After the baseline Member Server is joined to a domain environment, there is no need to use local accounts to access the server from the network. Domain accounts can access the server for administration and end-user processing. This user right supersedes the Allow log on through Remote Desktop Services user right if an account is subject to both policies.

  - Level 1 - Domain Controller. The recommended state for this setting is: Guests.
  - Level 1 - Member Server. The recommended state for this setting is: Guests, Local account.

  Caution: Configuring a standalone (non-domain-joined) server as described above may result in an inability to remotely administer the server.

  Note: The security identifier Local account is not available in Server 2008 R2 and Server 2012 (non-R2) unless MSKB 2871997 has been installed.

  Note #2: In all versions of Windows Server prior to Server 2008 R2, Remote Desktop Services was known as Terminal Services, so you should substitute the older term if comparing against an older OS.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.2.21'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': ['2.2.25', '2.2.26']
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M3', 'Sichere Administration', 'SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  attribute('se_deny_remote_interactive_logon_right').each do |entry|
    describe security_policy do
      its('SeDenyRemoteInteractiveLogonRight') { should include entry }
    end
  end
end

control 'windows-031' do
  title 'Configure \'Enable computer and user accounts to be trusted for delegation\''
  desc 'This policy setting allows users to change the Trusted for Delegation setting on a computer object in Active Directory. Abuse of this privilege could allow unauthorized users to impersonate other users on the network.

  - Level 1 - Domain Controller. The recommended state for this setting is: Administrators.
  - Level 1 - Member Server. The recommended state for this setting is: No One.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.2.22'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': ['2.2.27', '2.2.28']
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M3', 'Sichere Administration', 'SYS.1.2.2.M4', 'Sichere Konfiguration', 'SYS.1.2.2.M5', 'Schutz vor Schadsoftware', 'SYS.1.2.2.M6', 'Sichere Authentisierung und Autorisierung']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe security_policy do
    its('SeEnableDelegationPrivilege') { should eq attribute('se_enable_delegation_privilege') }
  end
end

control 'windows-032' do
  title 'Ensure \'Force shutdown from a remote system\' is set to \'Administrators\''
  desc 'This policy setting allows users to shut down Windows Vista-based and newer computers from remote locations on the network. Anyone who has been assigned this user right can cause a denial of service (DoS) condition, which would make the computer unavailable to service user requests. Therefore, it is recommended that only highly trusted administrators be assigned this user right.

  The recommended state for this setting is: Administrators.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.2.23'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.2.29'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M3', 'Sichere Administration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe security_policy do
    its('SeRemoteShutdownPrivilege') { should eq ['S-1-5-32-544'] }
  end
end

control 'windows-033' do
  title 'Ensure \'Generate security audits\' is set to \'LOCAL SERVICE, NETWORK SERVICE\''
  desc 'This policy setting determines which users or processes can generate audit records in the Security log.
  The recommended state for this setting is: LOCAL SERVICE, NETWORK SERVICE.

  Note: This user right is considered a "sensitive privilege" for the purposes of auditing.

  Note #2: A Member Server that holds the Web Server (IIS) Role with Web Server Role Service will require a special exception to this recommendation, to allow IIS application pool(s) to be granted this user right.

  Note #3: A Member Server that holds the Active Directory Federation Services Role will require a special exception to this recommendation, to allow the NT SERVICE\ADFSSrv and NT SERVICE\DRS services, as well as the associated Active Directory Federation Services service account, to be granted this user right.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.2.24'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.2.30'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M3', 'Sichere Administration', 'SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe security_policy do
    its('SeAuditPrivilege') { should eq ['S-1-5-19', 'S-1-5-20'] }
  end
end

control 'windows-034' do
  title 'Configure \'Impersonate a client after authentication\''
  desc 'The policy setting allows programs that run on behalf of a user to impersonate that user (or another specified account) so that they can act on behalf of the user. If this user right is required for this kind of impersonation, an unauthorized user will not be able to convince a client to connect—for example, by remote procedure call (RPC) or named pipes—to a service that they have created to impersonate that client, which could elevate the unauthorized user\'s permissions to administrative or system levels.

  Services that are started by the Service Control Manager have the built-in Service group added by default to their access tokens. COM servers that are started by the COM infrastructure and configured to run under a specific account also have the Service group added to their access tokens. As a result, these processes are assigned this user right when they are started.

  Also, a user can impersonate an access token if any of the following conditions exist:
  - The access token that is being impersonated is for this user.
  - The user, in this logon session, logged on to the network with explicit credentials to create the access token.
  - The requested level is less than Impersonate, such as Anonymous or Identify.

  An attacker with the Impersonate a client after authentication user right could create a service, trick a client to make them connect to the service, and then impersonate that client to elevate the attacker\'s level of access to that of the client.

  - Level 1 - Domain Controller. The recommended state for this setting is: Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE.
  - Level 1 - Member Server. The recommended state for this setting is: Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE and (when the Web Server (IIS) Role with Web Services Role Service is installed) IIS_IUSRS.

  Note: This user right is considered a "sensitive privilege" for the purposes of auditing.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.2.25'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': ['2.2.31', '2.2.32']
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M3', 'Sichere Administration', 'SYS.1.2.2.M6', 'Sichere Authentisierung und Autorisierung']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe security_policy do
    its('SeImpersonatePrivilege') { should eq attribute('se_impersonate_privilege') }
  end
end

control 'windows-035' do
  title 'Ensure \'Increase scheduling priority\' is set to \'Administrators\''
  desc 'This policy setting determines whether users can increase the base priority class of a process. (It is not a privileged operation to increase relative priority within a priority class.) This user right is not required by administrative tools that are supplied with the operating system but might be required by software development tools.

  The recommended state for this setting is: Administrators.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.2.26'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.2.33'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe security_policy do
    its('SeIncreaseBasePriorityPrivilege') { should eq ['S-1-5-32-544'] }
  end
end

control 'windows-036' do
  title 'Ensure \'Load and unload device drivers\' is set to \'Administrators\''
  desc 'This policy setting allows users to dynamically load a new device driver on a system. An attacker could potentially use this capability to install malicious code that appears to be a device driver. This user right is required for users to add local printers or printer drivers in Windows Vista.

  The recommended state for this setting is: Administrators.

  Note: This user right is considered a "sensitive privilege" for the purposes of auditing.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.2.27'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.2.34'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration', 'SYS.1.2.2.M5', 'Schutz vor Schadsoftware']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe security_policy do
    its('SeLoadDriverPrivilege') { should eq attribute('se_load_driver_privilege') }
  end
end

control 'windows-037' do
  title 'Ensure \'Lock pages in memory\' is set to \'No One\''
  desc 'This policy setting allows a process to keep data in physical memory, which prevents the system from paging the data to virtual memory on disk. If this user right is assigned, significant degradation of system performance can occur.

  The recommended state for this setting is: No One.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.2.28'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.2.35'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe security_policy do
    its('SeLockMemoryPrivilege') { should eq [] }
  end
end

control 'windows-038' do
  title 'Ensure \'Log on as a batch job\' is set to \'Administrators\' (DC only)'
  desc 'This policy setting allows accounts to log on using the task scheduler service. Because the task scheduler is often used for administrative purposes, it may be needed in enterprise environments. However, its use should be restricted in high security environments to prevent misuse of system resources or to prevent attackers from using the right to launch malicious code after gaining user level access to a computer.

  The recommended state for this setting is: Administrators.'
  impact 0.5
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.2.29'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.2.36'
  tag 'level': '2'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('This Control only executes if attribute(\'level_1_or_2\') is set to 2 and attribute(\'ms_or_dc\') is set to DC') do
    ((attribute('level_1_or_2') == 2) && (attribute('ms_or_dc') == 'DC'))
  end
  describe security_policy do
    its('SeBatchLogonRight') { should eq attribute('se_batch_logon_right') }
  end
end

control 'windows-039' do
  title 'Configure \'Manage auditing and security log\''
  desc 'This policy setting determines which users can change the auditing options for files and directories and clear the Security log.

  For environments running Microsoft Exchange Server, the Exchange Servers group must possess this privilege on Domain Controllers to properly function. Given this, DCs that grant the Exchange Servers group this privilege also conform to this benchmark. If the environment does not use Microsoft Exchange Server, then this privilege should be limited to only Administrators on DCs.

  - Level 1 - Domain Controller. The recommended state for this setting is: Administrators and (when Exchange is running in the environment) Exchange Servers.
  - Level 1 - Member Server. The recommended state for this setting is: Administrators.

  Note: This user right is considered a "sensitive privilege" for the purposes of auditing.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.2.30'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.2.38'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M3', 'Sichere Administration', 'SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe security_policy do
    its('SeSecurityPrivilege') { should eq attribute('se_security_privilege') }
  end
end

control 'windows-040' do
  title 'Ensure \'Modify an object label\' is set to \'No One\''
  desc 'This privilege determines which user accounts can modify the integrity label of objects, such as files, registry keys, or processes owned by other users. Processes running under a user account can modify the label of an object owned by that user to a lower level without this privilege.

  The recommended state for this setting is: No One.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.2.31'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.2.39'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe security_policy do
    its('SeRelabelPrivilege') { should eq [] }
  end
end

control 'windows-041' do
  title 'Ensure \'Modify firmware environment values\' is set to \'Administrators\''
  desc 'This policy setting allows users to configure the system-wide environment variables that affect hardware configuration. This information is typically stored in the Last Known Good Configuration. Modification of these values and could lead to a hardware failure that would result in a denial of service condition.
  The recommended state for this setting is: Administrators.

  Note: This user right is considered a "sensitive privilege" for the purposes of auditing.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.2.32'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.2.40'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration', 'SYS.1.2.2.M5', 'Schutz vor Schadsoftware']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe security_policy do
    its('SeSystemEnvironmentPrivilege') { should eq ['S-1-5-32-544'] }
  end
end

control 'windows-042' do
  title 'Ensure \'Perform volume maintenance tasks\' is set to \'Administrators\''
  desc 'This policy setting allows users to manage the system\'s volume or disk configuration, which could allow a user to delete a volume and cause data loss as well as a denial-ofservice condition.

  The recommended state for this setting is: Administrators.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.2.33'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.2.41'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe security_policy do
    its('SeManageVolumePrivilege') { should eq ['S-1-5-32-544'] }
  end
end

control 'windows-043' do
  title 'Ensure \'Profile single process\' is set to \'Administrators\''
  desc 'This policy setting determines which users can use tools to monitor the performance of non-system processes. Typically, you do not need to configure this user right to use the Microsoft Management Console (MMC) Performance snap-in. However, you do need this user right if System Monitor is configured to collect data using Windows Management Instrumentation (WMI). Restricting the Profile single process user right prevents intruders from gaining additional information that could be used to mount an attack on the system.

  The recommended state for this setting is: Administrators.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.2.34'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.2.42'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe security_policy do
    its('SeProfileSingleProcessPrivilege') { should eq ['S-1-5-32-544'] }
  end
end

control 'windows-044' do
  title 'Ensure \'Profile system performance\' is set to \'Administrators, NT SERVICE\WdiServiceHost\''
  desc 'This policy setting allows users to use tools to view the performance of different system processes, which could be abused to allow attackers to determine a system\'s active processes and provide insight into the potential attack surface of the computer.

  The recommended state for this setting is: Administrators, NT SERVICE\WdiServiceHost.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.2.35'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.2.43'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe security_policy do
    its('SeSystemProfilePrivilege') { should eq ['S-1-5-32-544', 'S-1-5-80-3139157870-2983391045-3678747466-658725712-1809340420'] }
  end
end

control 'windows-045' do
  title 'Ensure \'Replace a process level token\' is set to \'LOCAL SERVICE, NETWORK SERVICE\''
  desc 'This policy setting allows one process or service to start another service or process with a different security access token, which can be used to modify the security access token of that sub-process and result in the escalation of privileges.

  The recommended state for this setting is: LOCAL SERVICE, NETWORK SERVICE.

  Note: This user right is considered a "sensitive privilege" for the purposes of auditing.

  Note #2: A Member Server that holds the Web Server (IIS) Role with Web Server Role Service will require a special exception to this recommendation, to allow IIS application pool(s) to be granted this user right.

  Note #3: A Member Server with Microsoft SQL Server installed will require a special exception to this recommendation for additional SQL-generated entries to be granted this user right.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.2.36'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.2.44'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe security_policy do
    its('SeAssignPrimaryTokenPrivilege') { should eq attribute('se_assign_primary_token_privilege') }
  end
end

control 'windows-046' do
  title 'Ensure \'Restore files and directories\' is set to \'Administrators\''
  desc 'This policy setting determines which users can bypass file, directory, registry, and other persistent object permissions when restoring backed up files and directories on computers that run Windows Vista (or newer) in your environment. This user right also determines which users can set valid security principals as object owners; it is similar to the Back up files and directories user right.

  The recommended state for this setting is: Administrators.

  Note: This user right is considered a "sensitive privilege" for the purposes of auditing.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.2.37'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.2.45'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration', 'SYS.1.2.2.M8', 'Schutz der Systemintegrität']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe security_policy do
    its('SeRestorePrivilege') { should eq attribute('se_restore_privilege') }
  end
end

control 'windows-047' do
  title 'Ensure \'Shut down the system\' is set to \'Administrators\''
  desc 'This policy setting determines which users who are logged on locally to the computers in your environment can shut down the operating system with the Shut Down command. Misuse of this user right can result in a denial of service condition.

  The recommended state for this setting is: Administrators.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.2.38'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.2.46'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe security_policy do
    its('SeShutdownPrivilege') { should eq ['S-1-5-32-544'] }
  end
end

control 'windows-048' do
  title 'Ensure \'Synchronize directory service data\' is set to \'No One\' (DC only)'
  desc 'This security setting determines which users and groups have the authority to synchronize all directory service data. This is also known as Active Directory synchronization.

  The recommended state for this setting is: No One.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.2.39'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.2.47'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration', 'SYS.1.2.2.M5', 'Schutz vor Schadsoftware', 'SYS.1.2.2.M8', 'Schutz der Systemintegrität']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('This Control only executes if attribute(\'ms_or_dc\') is set to MS') do
    attribute('ms_or_dc') == 'DC'
  end
  describe security_policy do
    its('SeSyncAgentPrivilege') { should eq [] }
  end
end

control 'windows-049' do
  title 'Ensure \'Take ownership of files or other objects\' is set to \'Administrators\''
  desc 'This policy setting allows users to take ownership of files, folders, registry keys, processes, or threads. This user right bypasses any permissions that are in place to protect objects to give ownership to the specified user.

  The recommended state for this setting is: Administrators.

  Note: This user right is considered a "sensitive privilege" for the purposes of auditing.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.2.40'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.2.48'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']

  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe security_policy do
    its('SeTakeOwnershipPrivilege') { should eq ['S-1-5-32-544'] }
  end
end

control 'windows-050' do
  title 'Ensure \'Accounts: Administrator account status\' is set to \'Disabled\''
  desc 'This policy setting enables or disables the Administrator account during normal operation. When a computer is booted into safe mode, the Administrator account is always enabled, regardless of how this setting is configured. Note that this setting will have no impact when applied to the Domain Controllers organizational unit via group policy because Domain Controllers have no local account database. It can be configured at the domain level via group policy, similar to account lockout and password policy settings.

  The recommended state for this setting is: Disabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.1.1'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.1.1'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M3', 'Sichere Administration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('This Control only executes if attribute(\'ms_or_dc\') is set to MS') do
    attribute('ms_or_dc') == 'MS'
  end
  describe(users.where { uid =~ /S\-1\-5\-21\-\d+\-\d+\-\d+\-500/ }) do
    it { should exist }
    it { should be_disabled }
  end
end

control 'windows-051' do
  title 'Ensure \'Accounts: Block Microsoft accounts\' is set to \'Users can\'t add or log on with Microsoft accounts\''
  desc 'This policy setting prevents users from adding new Microsoft accounts on this computer.

  The recommended state for this setting is: Users can\'t add or log on with Microsoft accounts.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.1.2'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.1.2'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M3', 'Sichere Administration', 'SYS.1.2.2.M6', 'Sichere Authentisierung und Autorisierung']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System') do
    it { should exist }
    it { should have_property 'NoConnectedUser' }
    its('NoConnectedUser') { should eq 3 }
  end
end

control 'windows-052' do
  title 'Ensure \'Accounts: Guest account status\' is set to \'Disabled\''
  desc 'This policy setting determines whether the Guest account is enabled or disabled. The Guest account allows unauthenticated network users to gain access to the system.

  The recommended state for this setting is: Disabled.

  Note: This setting will have no impact when applied to the Domain Controllers organizational unit via group policy because Domain Controllers have no local account database. It can be configured at the domain level via group policy, similar to account lockout and password policy settings.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.1.3'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.1.3'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration', 'SYS.1.2.2.M5', 'Schutz vor Schadsoftware', 'SYS.1.2.2.M6', 'Sichere Authentisierung und Autorisierung']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('This Control only executes if attribute(\'ms_or_dc\') is set to MS') do
    attribute('ms_or_dc') == 'MS'
  end
  describe(users.where { uid =~ /S\-1\-5\-21\-\d+\-\d+\-\d+\-501/ }) do
    it { should exist }
    it { should be_disabled }
  end
end

control 'windows-053' do
  title 'Ensure \'Accounts: Limit local account use of blank passwords to console logon only\' is set to \'Enabled\''
  desc 'This policy setting determines whether local accounts that are not password protected can be used to log on from locations other than the physical computer console. If you enable this policy setting, local accounts that have blank passwords will not be able to log on to the network from remote client computers. Such accounts will only be able to log on at the keyboard of the computer.

  The recommended state for this setting is: Enabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.1.4'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.1.4'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration', 'SYS.1.2.2.M6', 'Sichere Authentisierung und Autorisierung']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Lsa') do
    it { should exist }
    it { should have_property 'LimitBlankPasswordUse' }
    its('LimitBlankPasswordUse') { should eq 1 }
  end
end

control 'windows-054' do
  title 'Configure \'Accounts: Rename administrator account\''
  desc 'The built-in local administrator account is a well-known account name that attackers will target. It is recommended to choose another name for this account, and to avoid names that denote administrative or elevated access accounts. Be sure to also change the default description for the local administrator (through the Computer Management console). On Domain Controllers, since they do not have their own local accounts, this rule refers to the built-in Administrator account that was established when the domain was first created.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.1.5'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.1.5'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M3', 'Sichere Administration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe user('Administrator') do
    it { should_not exist }
  end
end

control 'windows-055' do
  title 'Configure \'Accounts: Rename guest account\''
  desc 'The built-in local guest account is another well-known name to attackers. It is recommended to rename this account to something that does not indicate its purpose. Even if you disable this account, which is recommended, ensure that you rename it for added security. On Domain Controllers, since they do not have their own local accounts, this rule refers to the built-in Guest account that was established when the domain was first created.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.1.6'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.1.6'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration', 'SYS.1.2.2.M6', 'Sichere Authentisierung und Autorisierung']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe user('Guest') do
    it { should_not exist }
  end
end

control 'windows-056' do
  title 'Ensure \'Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings\' is set to \'Enabled\''
  desc 'This policy setting allows administrators to enable the more precise auditing capabilities present in Windows Vista.

  The Audit Policy settings available in Windows Server 2003 Active Directory do not yet contain settings for managing the new auditing subcategories. To properly apply the auditing policies prescribed in this baseline, the Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings setting needs to be configured to Enabled.

  The recommended state for this setting is: Enabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.2.1'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.2.1'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M3', 'Sichere Administration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Lsa') do
    it { should exist }
    it { should have_property 'SCENoApplyLegacyAuditPolicy' }
    its('SCENoApplyLegacyAuditPolicy') { should eq 1 }
  end
end

control 'windows-057' do
  title 'Ensure \'Audit: Shut down system immediately if unable to log security audits\' is set to \'Disabled\''
  desc 'This policy setting determines whether the system shuts down if it is unable to log Security events. It is a requirement for Trusted Computer System Evaluation Criteria (TCSEC)-C2 and Common Criteria certification to prevent auditable events from occurring if the audit system is unable to log them. Microsoft has chosen to meet this requirement by halting the system and displaying a stop message if the auditing system experiences a failure. When this policy setting is enabled, the system will be shut down if a security audit cannot be logged for any reason.

  If the Audit: Shut down system immediately if unable to log security audits setting is enabled, unplanned system failures can occur. The administrative burden can be significant, especially if you also configure the Retention method for the Security log to Do not overwrite events (clear log manually). This configuration causes a repudiation threat (a backup operator could deny that they backed up or restored data) to become a denial of service (DoS) vulnerability, because a server could be forced to shut down if it is overwhelmed with logon events and other security events that are written to the Security log. Also, because the shutdown is not graceful, it is possible that irreparable damage to the operating system, applications, or data could result. Although the NTFS file system guarantees its integrity when an ungraceful computer shutdown occurs, it cannot guarantee that every data file for every application will still be in a usable form when the computer restarts.

  The recommended state for this setting is: Disabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.2.2'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.2.2'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration', 'SYS.1.2.2.M8', 'Schutz der Systemintegrität']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\LSA') do
    it { should exist }
    it { should have_property 'CrashOnAuditFail' }
    its('CrashOnAuditFail') { should eq 0 }
  end
end

control 'windows-058' do
  title 'Ensure \'Devices: Allowed to format and eject removable media\' is set to \'Administrators\''
  desc 'This policy setting determines who is allowed to format and eject removable NTFS media. You can use this policy setting to prevent unauthorized users from removing data on one computer to access it on another computer on which they have local administrator privileges.

  The recommended state for this setting is: Administrators.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.4.1'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.4.1'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon') do
    it { should exist }
    it { should have_property 'AllocateDASD' }
    its('AllocateDASD') { should eq 0 }
  end
end

control 'windows-059' do
  title 'Ensure \'Devices: Prevent users from installing printer drivers\' is set to \'Enabled\''
  desc 'For a computer to print to a shared printer, the driver for that shared printer must be installed on the local computer. This security setting determines who is allowed to install a printer driver as part of connecting to a shared printer.

  The recommended state for this setting is: Enabled.

  Note: This setting does not affect the ability to add a local printer. This setting does not affect Administrators.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.4.2'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.4.2'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration', 'SYS.1.2.2.M5', 'Schutz vor Schadsoftware', 'SYS.1.2.2.M8', 'Schutz der Systemintegrität']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Print\\Providers\\LanMan Print Services\\Servers') do
    it { should exist }
    it { should have_property 'AddPrinterDrivers' }
    its('AddPrinterDrivers') { should eq 1 }
  end
end

control 'windows-060' do
  title 'Ensure \'Domain controller: Allow server operators to schedule tasks\' is set to \'Disabled\' (DC only)'
  desc 'This policy setting determines whether members of the Server Operators group are allowed to submit jobs by means of the AT schedule facility. The impact of this policy setting configuration should be small for most organizations. Users, including those in the Server Operators group, will still be able to create jobs by means of the Task Scheduler Wizard, but those jobs will run in the context of the account with which the user authenticates when they set up the job.
  Note: An AT Service Account can be modified to select a different account rather than the LOCAL SYSTEM account. To change the account, open System Tools, click Scheduled Tasks, and then click Accessories folder. Then click AT Service Account on the Advanced menu.

  The recommended state for this setting is: Disabled. (DC only)'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.5.1'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.5.1'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M3', 'Sichere Administration'] # FIXME: check Baustein
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('This Control only executes if attribute(\'ms_or_dc\') is set to MS') do
    attribute('ms_or_dc') == 'DC'
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Lsa') do
    it { should exist }
    it { should have_property 'SubmitControl' }
    its('SubmitControl') { should eq 0 }
  end
end

control 'windows-061' do
  title 'Ensure \'Domain controller: LDAP server signing requirements\' is set to \'Require signing\' (DC only)'
  desc 'This policy setting determines whether the Lightweight Directory Access Protocol (LDAP) server requires LDAP clients to negotiate data signing.
  The recommended state for this setting is: Require signing.

  Note: Domain member computers must have Network security: LDAP signing requirements (Rule 2.3.11.8) set to Negotiate signing or higher. If not, they will fail to authenticate once the above Require signing value is configured on the Domain Controllers. Fortunately, Negotiate signing is the default in the client configuration.

  Note #2: This policy setting does not have any impact on LDAP simple bind (ldap_simple_bind) or LDAP simple bind through SSL (ldap_simple_bind_s). No Microsoft LDAP clients that are shipped with Windows XP Professional use LDAP simple bind or LDAP simple bind through SSL to talk to a Domain Controller.

  Note #3: Before enabling this setting, you should first ensure that there are no clients (including server-based applications) that are configured to authenticate with Active Directory via unsigned LDAP, because changing this setting will break those applications. Such applications should first be reconfigured to use signed LDAP, Secure LDAP (LDAPS), or IPsec-protected connections. For more information on how to identify whether your DCs are being accessed via unsigned LDAP (and where those accesses are coming from), see this Microsoft TechNet blog article: Identifying Clear Text LDAP binds to your DC’s – Practical Windows Security'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.5.2'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.5.2'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration', 'SYS.1.2.2.M6', 'Sichere Authentisierung und Autorisierung']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('This Control only executes if attribute(\'ms_or_dc\') is set to MS') do
    attribute('ms_or_dc') == 'DC'
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\NTDS\\Parameters') do
    it { should exist }
    it { should have_property 'LDAPServerIntegrity' }
    its('LDAPServerIntegrity') { should eq 2 }
  end
end

control 'windows-062' do
  title 'Ensure \'Domain controller: Refuse machine account password changes\' is set to \'Disabled\' (DC only)'
  desc 'This security setting determines whether Domain Controllers will refuse requests from member computers to change computer account passwords.

  The recommended state for this setting is: Disabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.5.3'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.5.3'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('This Control only executes if attribute(\'ms_or_dc\') is set to MS') do
    attribute('ms_or_dc') == 'DC'
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\Netlogon\\Parameters') do
    it { should exist }
    it { should have_property 'RefusePasswordChange' }
    its('RefusePasswordChange') { should eq 0 }
  end
end

control 'windows-063' do
  title 'Ensure \'Domain member: Digitally encrypt or sign secure channel data (always)\' is set to \'Enabled\''
  desc 'This policy setting determines whether all secure channel traffic that is initiated by the domain member must be signed or encrypted.

  The recommended state for this setting is: Enabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.6.1'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.6.1'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\Netlogon\\Parameters') do
    it { should exist }
    it { should have_property 'RequireSignOrSeal' }
    its('RequireSignOrSeal') { should eq 1 }
  end
end

control 'windows-064' do
  title 'Ensure \'Domain member: Digitally encrypt secure channel data (when possible)\' is set to \'Enabled\''
  desc 'This policy setting determines whether a domain member should attempt to negotiate encryption for all secure channel traffic that it initiates.

  The recommended state for this setting is: Enabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.6.2'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.6.2'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\Netlogon\\Parameters') do
    it { should exist }
    it { should have_property 'SealSecureChannel' }
    its('SealSecureChannel') { should eq 1 }
  end
end

control 'windows-065' do
  title 'Ensure \'Domain member: Digitally sign secure channel data (when possible)\' is set to \'Enabled\''
  desc 'This policy setting determines whether a domain member should attempt to negotiate whether all secure channel traffic that it initiates must be digitally signed. Digital signatures protect the traffic from being modified by anyone who captures the data as it traverses the network.

  The recommended state for this setting is: Enabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.6.3'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.6.3'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\Netlogon\\Parameters') do
    it { should exist }
    it { should have_property 'SignSecureChannel' }
    its('SignSecureChannel') { should eq 1 }
  end
end

control 'windows-066' do
  title 'Ensure \'Domain member: Disable machine account password changes\' is set to \'Disabled\''
  desc 'This policy setting determines whether a domain member can periodically change its computer account password. Computers that cannot automatically change their account passwords are potentially vulnerable, because an attacker might be able to determine the password for the system\'s domain account.

  The recommended state for this setting is: Disabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.6.4'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.6.4'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration', 'SYS.1.2.2.M8', 'Schutz der Systemintegrität']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\Netlogon\\Parameters') do
    it { should exist }
    it { should have_property 'DisablePasswordChange' }
    its('DisablePasswordChange') { should eq 0 }
  end
end

control 'windows-067' do
  title 'Ensure \'Domain member: Maximum machine account password age\' is set to \'30 or fewer days, but not 0\''
  desc 'This policy setting determines the maximum allowable age for a computer account password. By default, domain members automatically change their domain passwords every 30 days.

  The recommended state for this setting is: 30 or fewer days, but not 0.

  Note: A value of 0 does not conform to the benchmark as it disables maximum password age.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.6.5'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.6.5'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\Netlogon\\Parameters') do
    it { should exist }
    it { should have_property 'MaximumPasswordAge' }
    its('MaximumPasswordAge') { should cmp > 0 }
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\Netlogon\\Parameters') do
    it { should exist }
    it { should have_property 'MaximumPasswordAge' }
    its('MaximumPasswordAge') { should cmp <= 30 }
  end
end

control 'windows-068' do
  title 'Ensure \'Domain member: Require strong (Windows 2000 or later) session key\' is set to \'Enabled\''
  desc 'When this policy setting is enabled, a secure channel can only be established with Domain Controllers that are capable of encrypting secure channel data with a strong (128-bit) session key.

  To enable this policy setting, all Domain Controllers in the domain must be able to encrypt secure channel data with a strong key, which means all Domain Controllers must be running Microsoft Windows 2000 or newer.

  The recommended state for this setting is: Enabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.6.6'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.6.6'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration', 'SYS.1.2.2.M6', 'Sichere Authentisierung und Autorisierung', 'SYS.1.2.2.M8', 'Schutz der Systemintegrität']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\Netlogon\\Parameters') do
    it { should exist }
    it { should have_property 'RequireStrongKey' }
    its('RequireStrongKey') { should eq 1 }
  end
end

control 'windows-069' do
  title 'Ensure \'Interactive logon: Do not display last user name\' is set to \'Enabled\''
  desc 'This policy setting determines whether the account name of the last user to log on to the client computers in your organization will be displayed in each computer\'s respective Windows logon screen. Enable this policy setting to prevent intruders from collecting account names visually from the screens of desktop or laptop computers in your organization.

  The recommended state for this setting is: Enabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.7.1'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.7.1'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M3', 'Sichere Administration', 'SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System') do
    it { should exist }
    it { should have_property 'DontDisplayLastUserName' }
    its('DontDisplayLastUserName') { should eq 1 }
  end
end

control 'windows-070' do
  title 'Ensure \'Interactive logon: Do not require CTRL+ALT+DEL\' is set to \'Disabled\''
  desc 'Microsoft developed this feature to make it easier for users with certain types of physical impairments to log on to computers that run Windows. If users are not required to press CTRL+ALT+DEL, they are susceptible to attacks that attempt to intercept their passwords. If CTRL+ALT+DEL is required before logon, user passwords are communicated by means of a trusted path.

  An attacker could install a Trojan horse program that looks like the standard Windows logon dialog box and capture the user\'s password. The attacker would then be able to log on to the compromised account with whatever level of privilege that user has.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.7.2'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.7.2'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M3', 'Sichere Administration', 'SYS.1.2.2.M6', 'Sichere Authentisierung und Autorisierung']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System') do
    it { should exist }
    it { should have_property 'DisableCAD' }
    its('DisableCAD') { should cmp eq 0 }
  end
end

control 'windows-071' do
  title 'Ensure \'Interactive logon: Machine inactivity limit\' is set to \'900 or fewer second(s), but not 0\''
  desc 'Windows notices inactivity of a logon session, and if the amount of inactive time exceeds the inactivity limit, then the screen saver will run, locking the session.

  The recommended state for this setting is: 900 or fewer second(s), but not 0.

  Note: A value of 0 does not conform to the benchmark as it disables the machine inactivity limit.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.7.3'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.7.3'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M6', 'Sichere Authentisierung und Autorisierung']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System') do
    it { should exist }
    it { should have_property 'InactivityTimeoutSecs' }
    its('InactivityTimeoutSecs') { should_not eq 0 }
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System') do
    it { should exist }
    it { should have_property 'InactivityTimeoutSecs' }
    its('InactivityTimeoutSecs') { should cmp <= 900 }
  end
end

control 'windows-072' do
  title 'Configure \'Interactive logon: Message text for users attempting to log on\''
  desc 'This policy setting specifies a text message that displays to users when they log on. Configure this setting in a manner that is consistent with the security and operational requirements of your organization.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.7.4'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.7.4'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System') do
    it { should exist }
    it { should have_property 'LegalNoticeText' }
    its('LegalNoticeText') { should match(//) }
  end
end

control 'windows-073' do
  title 'Configure \'Interactive logon: Message title for users attempting to log on\''
  desc 'This policy setting specifies the text displayed in the title bar of the window that users see when they log on to the system. Configure this setting in a manner that is consistent with the security and operational requirements of your organization.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.7.5'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.7.5'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System') do
    it { should exist }
    it { should have_property 'LegalNoticeCaption' }
    its('LegalNoticeCaption') { should match(//) }
  end
end

control 'windows-074' do
  title 'Ensure \'Interactive logon: Number of previous logons to cache (in case domain controller is not available)\' is set to \'4 or fewer logon(s)\''
  desc 'This policy setting determines whether a user can log on to a Windows domain using cached account information. Logon information for domain accounts can be cached locally to allow users to log on even if a Domain Controller cannot be contacted. This policy setting determines the number of unique users for whom logon information is cached locally. If this value is set to 0, the logon cache feature is disabled. An attacker who is able to access the file system of the server could locate this cached information and use a brute force attack to determine user passwords.

  The recommended state for this setting is: 4 or fewer logon(s).'
  impact 0.5
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.7.6'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.7.6'
  tag 'level': '2'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('This Control only executes if attribute(\'level_1_or_2\') is set to 2 and attribute(\'ms_or_dc\') is set to MS') do
    ((attribute('level_1_or_2') == 2) && (attribute('ms_or_dc') == 'MS'))
  end
  describe registry_key('HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon') do
    it { should exist }
    its('CachedLogonsCount') { should be <= 4 }
  end
end

control 'windows-075' do
  title 'Ensure \'Interactive logon: Prompt user to change password before expiration\' is set to \'between 5 and 14 days\''
  desc 'This policy setting determines how far in advance users are warned that their password will expire. It is recommended that you configure this policy setting to at least 5 days but no more than 14 days to sufficiently warn users when their passwords will expire.

  The recommended state for this setting is: between 5 and 14 days.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.7.7'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.7.7'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration', 'SYS.1.2.2.M6', 'Sichere Authentisierung und Autorisierung']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon') do
    it { should exist }
    it { should have_property 'PasswordExpiryWarning' }
    its('PasswordExpiryWarning') { should cmp <= 14 }
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon') do
    it { should exist }
    it { should have_property 'passwordexpirywarning' }
    its('passwordexpirywarning') { should cmp >= 5 }
  end
end

control 'windows-076' do
  title 'Ensure \'Interactive logon: Require Domain Controller Authentication to unlock workstation\' is set to \'Enabled\''
  desc 'Logon information is required to unlock a locked computer. For domain accounts, this security setting determines whether it is necessary to contact a Domain Controller to unlock a computer.

  The recommended state for this setting is: Enabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.7.8'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.7.8'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration', 'SYS.1.2.2.M6', 'Sichere Authentisierung und Autorisierung']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('This Control only executes if attribute(\'ms_or_dc\') is set to MS') do
    attribute('ms_or_dc') == 'MS'
  end
  describe registry_key('HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon') do
    it { should exist }
    it { should have_property 'ForceUnlockLogon' }
    its('ForceUnlockLogon') { should eq 1 }
  end
end

control 'windows-077' do
  title 'Ensure \'Interactive logon: Smart card removal behavior\' is set to \'Lock Workstation\' or higher'
  desc 'This policy setting determines what happens when the smart card for a logged-on user is removed from the smart card reader.

  The recommended state for this setting is: Lock Workstation. Configuring this setting to Force Logoff or Disconnect if a Remote Desktop Services session also conforms to the benchmark.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.7.9'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.7.9'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M6', 'Sichere Authentisierung und Autorisierung']

  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon') do
    it { should exist }
    it { should have_property 'ScRemoveOption' }
    its('ScRemoveOption') { should match(//) }
  end
end

control 'windows-078' do
  title 'Ensure \'Microsoft network client: Digitally sign communications (always)\' is set to \'Enabled\''
  desc 'This policy setting determines whether packet signing is required by the SMB client component.

  Note: When Windows Vista-based computers have this policy setting enabled and they connect to file or print shares on remote servers, it is important that the setting is synchronized with its companion setting, Microsoft network server: Digitally sign communications (always), on those servers. For more information about these settings, see the "Microsoft network client and server: Digitally sign communications (four related settings)" section in Chapter 5 of the Threats and Countermeasures guide.

  The recommended state for this setting is: Enabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.8.1'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.8.1'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration', 'SYS.1.2.2.M6', 'Sichere Authentisierung und Autorisierung']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters') do
    it { should exist }
    it { should have_property 'RequireSecuritySignature' }
    its('RequireSecuritySignature') { should eq 1 }
  end
end

control 'windows-079' do
  title 'Ensure \'Microsoft network client: Digitally sign communications (if server agrees)\' is set to \'Enabled\''
  desc 'This policy setting determines whether the SMB client will attempt to negotiate SMB packet signing.

  Note: Enabling this policy setting on SMB clients on your network makes them fully effective for packet signing with all clients and servers in your environment.

  The recommended state for this setting is: Enabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.8.2'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.8.2'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M6', 'Sichere Authentisierung und Autorisierung']

  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters') do
    it { should exist }
    it { should have_property 'EnableSecuritySignature' }
    its('EnableSecuritySignature') { should eq 1 }
  end
end

control 'windows-080' do
  title 'Ensure \'Microsoft network client: Send unencrypted password to third-party SMB servers\' is set to \'Disabled\''
  desc 'This policy setting determines whether the SMB redirector will send plaintext passwords during authentication to third-party SMB servers that do not support password encryption.

  It is recommended that you disable this policy setting unless there is a strong business case to enable it. If this policy setting is enabled, unencrypted passwords will be allowed across the network.

  The recommended state for this setting is: Disabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.8.3'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.8.3'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M6', 'Sichere Authentisierung und Autorisierung']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters') do
    it { should exist }
    it { should have_property 'EnablePlainTextPassword' }
    its('EnablePlainTextPassword') { should eq 0 }
  end
end

control 'windows-081' do
  title 'Ensure \'Microsoft network server: Amount of idle time required before suspending session\' is set to \'15 or fewer minute(s), but not 0\''
  desc 'This policy setting allows you to specify the amount of continuous idle time that must pass in an SMB session before the session is suspended because of inactivity. Administrators can use this policy setting to control when a computer suspends an inactive SMB session. If client activity resumes, the session is automatically reestablished.

  A value of 0 appears to allow sessions to persist indefinitely. The maximum value is 99999, which is over 69 days; in effect, this value disables the setting.

  The recommended state for this setting is: 15 or fewer minute(s), but not 0.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.9.1'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.9.1'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration', 'SYS.1.2.2.M6', 'Sichere Authentisierung und Autorisierung']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\LanManServer\\Parameters') do
    it { should exist }
    it { should have_property 'AutoDisconnect' }
    its('AutoDisconnect') { should eq 15 }
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\LanManServer\\Parameters') do
    it { should exist }
    it { should have_property 'AutoDisconnect' }
    its('AutoDisconnect') { should_not eq 0 }
  end
end

control 'windows-082' do
  title 'Ensure \'Microsoft network server: Digitally sign communications (always)\' is set to \'Enabled\''
  desc 'This policy setting determines whether packet signing is required by the SMB server component. Enable this policy setting in a mixed environment to prevent downstream clients from using the workstation as a network server.

  The recommended state for this setting is: Enabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.9.2'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.9.2'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration', 'SYS.1.2.2.M6', 'Sichere Authentisierung und Autorisierung']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\LanManServer\\Parameters') do
    it { should exist }
    it { should have_property 'RequireSecuritySignature' }
    its('RequireSecuritySignature') { should eq 1 }
  end
end

control 'windows-083' do
  title 'Ensure \'Microsoft network server: Digitally sign communications (if client agrees)\' is set to \'Enabled\''
  desc 'This policy setting determines whether the SMB server will negotiate SMB packet signing with clients that request it. If no signing request comes from the client, a connection will be allowed without a signature if the Microsoft network server: Digitally sign communications (always) setting is not enabled.

  Note: Enable this policy setting on SMB clients on your network to make them fully effective for packet signing with all clients and servers in your environment.

  The recommended state for this setting is: Enabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.9.3'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.9.3'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration', 'SYS.1.2.2.M6', 'Sichere Authentisierung und Autorisierung']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\LanManServer\\Parameters') do
    it { should exist }
    it { should have_property 'EnableSecuritySignature' }
    its('EnableSecuritySignature') { should eq 1 }
  end
end

control 'windows-084' do
  title 'Ensure \'Microsoft network server: Disconnect clients when logon hours expire\' is set to \'Enabled\''
  desc 'This security setting determines whether to disconnect users who are connected to the local computer outside their user account\'s valid logon hours. This setting affects the Server Message Block (SMB) component. If you enable this policy setting you should also enable Network security: Force logoff when logon hours expire (Rule 2.3.11.6).

  If your organization configures logon hours for users, this policy setting is necessary to ensure they are effective.

  The recommended state for this setting is: Enabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.9.4'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.9.4'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration', 'SYS.1.2.2.M6', 'Sichere Authentisierung und Autorisierung']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\LanManServer\\Parameters') do
    it { should exist }
    it { should have_property 'EnableForcedLogoff' }
    its('EnableForcedLogoff') { should eq 1 }
  end
end

control 'windows-085' do
  title 'Ensure \'Microsoft network server: Server SPN target name validation level\' is set to \'Accept if provided by client\' or higher\''
  desc 'This policy setting controls the level of validation a computer with shared folders or printers (the server) performs on the service principal name (SPN) that is provided by the client computer when it establishes a session using the server message block (SMB) protocol.

  The server message block (SMB) protocol provides the basis for file and print sharing and other networking operations, such as remote Windows administration. The SMB protocol supports validating the SMB server service principal name (SPN) within the authentication blob provided by a SMB client to prevent a class of attacks against SMB servers referred to as SMB relay attacks. This setting will affect both SMB1 and SMB2.

  The recommended state for this setting is: Accept if provided by client. Configuring this setting to Required from client also conforms to the benchmark.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.9.5'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.9.5'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration', 'SYS.1.2.2.M6', 'Sichere Authentisierung und Autorisierung']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('This Control only executes if attribute(\'ms_or_dc\') is set to MS') do
    attribute('ms_or_dc') == 'MS'
  end
  describe registry_key('HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanManServer\\Parameters') do
    it { should exist }
    it { should have_property 'SMBServerNameHardeningLevel' }
    its('SMBServerNameHardeningLevel') { should be >= 1 }
    its('SMBServerNameHardeningLevel') { should be <= 2 }
  end
end

control 'windows-086' do
  title 'Ensure \'Network access: Allow anonymous SID/Name translation\' is set to \'Disabled\''
  desc 'This policy setting determines whether an anonymous user can request security identifier (SID) attributes for another user, or use a SID to obtain its corresponding user name.

  The recommended state for this setting is: Disabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.10.1'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.10.1'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe security_policy do
    it { should exist }
    it { should have_property 'LSAAnonymousNameLookup' }
    its('LSAAnonymousNameLookup') { should eq 0 }
  end
end

control 'windows-087' do
  title 'Ensure \'Network access: Do not allow anonymous enumeration of SAM accounts\' is set to \'Enabled\''
  desc 'This policy setting controls the ability of anonymous users to enumerate the accounts in the Security Accounts Manager (SAM). If you enable this policy setting, users with anonymous connections will not be able to enumerate domain account user names on the systems in your environment. This policy setting also allows additional restrictions on anonymous connections.

  The recommended state for this setting is: Enabled.

  Note: This policy has no effect on Domain Controllers.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.10.2'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.10.2'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('This Control only executes if attribute(\'ms_or_dc\') is set to MS') do
    attribute('ms_or_dc') == 'MS'
  end
  describe registry_key('HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa') do
    it { should exist }
    it { should have_property 'RestrictAnonymousSAM' }
    its('RestrictAnonymousSAM') { should eq 1 }
  end
end

control 'windows-088' do
  title 'Ensure \'Network access: Do not allow anonymous enumeration of SAM accounts and shares\' is set to \'Enabled\''
  desc 'This policy setting controls the ability of anonymous users to enumerate SAM accounts as well as shares. If you enable this policy setting, anonymous users will not be able to enumerate domain account user names and network share names on the systems in your environment.

  The recommended state for this setting is: Enabled.

  Note: This policy has no effect on Domain Controllers.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.10.3'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.10.3'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('This Control only executes if attribute(\'ms_or_dc\') is set to MS') do
    attribute('ms_or_dc') == 'MS'
  end
  describe registry_key('HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa') do
    it { should exist }
    it { should have_property 'RestrictAnonymous' }
    its('RestrictAnonymous') { should eq 1 }
  end
end

control 'windows-089' do
  title 'Ensure \'Network access: Do not allow storage of passwords and credentials for network authentication\' is set to \'Enabled\''
  desc 'This policy setting determines whether Credential Manager (formerly called Stored User Names and Passwords) saves passwords or credentials for later use when it gains domain authentication.

  The recommended state for this setting is: Enabled.

  Note: Changes to this setting will not take effect until Windows is restarted.'
  impact 0.5
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.10.4'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.10.4'
  tag 'level': '2'
  tag 'bsi': ['SYS.1.2.2.M3', 'Sichere Administration'] # FIXME: check Baustein
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('This Control only executes if attribute(\'level_1_or_2\') is set to 2') do
    attribute('level_1_or_2') == 2
  end
  describe registry_key('HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa') do
    it { should exist }
    it { should have_property 'DisableDomainCreds' }
    its('DisableDomainCreds') { should eq 1 }
  end
end

control 'windows-090' do
  title 'Ensure \'Network access: Let Everyone permissions apply to anonymous users\' is set to \'Disabled\''
  desc 'This policy setting determines what additional permissions are assigned for anonymous connections to the computer.

  The recommended state for this setting is: Disabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.10.5'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.10.5'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Lsa') do
    it { should exist }
    it { should have_property 'EveryoneIncludesAnonymous' }
    its('EveryoneIncludesAnonymous') { should eq 1 }
  end
end

control 'windows-091' do
  title 'Configure \'Network access: Named Pipes that can be accessed anonymously\''
  desc 'This policy setting determines which communication sessions, or pipes, will have attributes and permissions that allow anonymous access.
  The recommended state for this setting is: LSARPC, NETLOGON, SAMR and (when the legacy Computer Browser service is enabled) BROWSER.

  The recommended state for this setting is:
  - Level 1 - Domain Controller. The recommended state for this setting is: LSARPC, NETLOGON, SAMR and (when the legacy Computer Browser service is enabled) BROWSER.
  - Level 1 - Member Server. The recommended state for this setting is: <blank> (i.e. None), or (when the legacy Computer Browser service is enabled) BROWSER.

  Note: A Member Server that holds the Remote Desktop Services Role with Remote Desktop Licensing Role Service will require a special exception to this recommendation, to allow the HydraLSPipe and TermServLicensing Named Pipes to be accessed anonymously.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.10.6'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': ['2.3.10.6', '2.3.10.7']
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanManServer\\Parameters') do
    it { should exist }
    it { should have_property 'NullSessionPipes' }
    its('NullSessionPipes') { should eq HKLM_NULL_SESSION_PIPES }
  end
end

control 'windows-092' do
  title 'Configure \'Network access: Remotely accessible registry paths\''
  desc 'This policy setting determines which registry paths will be accessible over the network, regardless of the users or groups listed in the access control list (ACL) of the winreg registry key.

  Note: This setting does not exist in Windows XP. There was a setting with that name in Windows XP, but it is called "Network access: Remotely accessible registry paths and subpaths" in Windows Server 2003, Windows Vista, and Windows Server 2008 (non-R2).

  Note #2: When you configure this setting you specify a list of one or more objects. The delimiter used when entering the list is a line feed or carriage return, that is, type the first object on the list, press the Enter button, type the next object, press Enter again, etc. The setting value is stored as a comma-delimited list in group policy security templates. It is also rendered as a comma-delimited list in Group Policy Editor\'s display pane and the Resultant Set of Policy console. It is recorded in the registry as a line-feed delimited list in a REG_MULTI_SZ value.

  The recommended state for this setting is:
  System\CurrentControlSet\Control\ProductOptions
  System\CurrentControlSet\Control\Server Applications
  Software\Microsoft\Windows NT\CurrentVersion'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.10.7'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.10.8'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKLM:\\System\\CurrentControlSet\\Control\\SecurePipeServers\\Winreg\\AllowedExactPaths') do
    it { should exist }
    it { should have_property 'Machine' }
    its('Machine') { should eq '{System\\CurrentControlSet\\Control\\ProductOptions,System\\CurrentControlSet\\Control\\Server Applications,Software\\Microsoft\\Windows NT\\CurrentVersion}' }
  end
end

control 'windows-093' do
  title 'Configure \'Network access: Remotely accessible registry paths and sub-paths\''
  desc 'This policy setting determines which registry paths and sub-paths will be accessible over the network, regardless of the users or groups listed in the access control list (ACL) of the winreg registry key.

  Note: In Windows XP this setting is called "Network access: Remotely accessible registry paths," the setting with that same name in Windows Vista, Windows Server 2008 (non-R2), and Windows Server 2003 does not exist in Windows XP.

  Note #2: When you configure this setting you specify a list of one or more objects. The delimiter used when entering the list is a line feed or carriage return, that is, type the first object on the list, press the Enter button, type the next object, press Enter again, etc. The setting value is stored as a comma-delimited list in group policy security templates. It is also rendered as a comma-delimited list in Group Policy Editor\'s display pane and the Resultant Set of Policy console. It is recorded in the registry as a line-feed delimited list in a REG_MULTI_SZ value.

  The recommended state for this setting is:
  System\CurrentControlSet\Control\Print\Printers
  System\CurrentControlSet\Services\Eventlog Software\Microsoft\OLAP Server
  Software\Microsoft\Windows NT\CurrentVersion\Print
  Software\Microsoft\Windows NT\CurrentVersion\Windows
  System\CurrentControlSet\Control\ContentIndex System\CurrentControlSet\Control\Terminal Server
  System\CurrentControlSet\Control\Terminal
  Server\UserConfig System\CurrentControlSet\Control\Terminal
  Server\DefaultUserConfiguration Software\Microsoft\Windows NT\CurrentVersion\Perflib
  System\CurrentControlSet\Services\SysmonLog

  The recommended state for servers that hold the Active Directory Certificate Services Role with Certification Authority Role Service includes the above list and:
  System\CurrentControlSet\Services\CertSvc

  The recommended state for servers that have the WINS Server Feature installed includes the above list and:
  System\CurrentControlSet\Services\WINS'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.10.8'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.10.9'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration', 'SYS.1.2.2.M8', 'Schutz der Systemintegrität']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  wins_installed = windows_feature('WINS').installed?
  ad_cert_installed = windows_feature('AD-Certificate').installed?

  if !wins_installed && !ad_cert_installed
    describe registry_key('HKLM:\\System\\CurrentControlSet\\Control\\SecurePipeServers\\Winreg\\AllowedPaths') do
      it { should exist }
      it { should have_property 'Machine' }
      its('Machine') { should eq '{System\\CurrentControlSet\\Control\\Print\\Printers,System\\CurrentControlSet\\Services\\Eventlog,Software\\Microsoft\\OLAP Server,Software\\Microsoft\\Windows NT\\CurrentVersion\\Print,Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows,System\\CurrentControlSet\\Control\\ContentIndex,System\\CurrentControlSet\\Control\\Terminal Server,System\\CurrentControlSet\\Control\\Terminal Server\\UserConfig,System\\CurrentControlSet\\Control\\Terminal Server\\DefaultUserConfiguration,Software\\Microsoft\\Windows NT\\CurrentVersion\\Perflib,System\\CurrentControlSet\\Services\\SysmonLog}' }
    end
  elsif wins_installed && !ad_cert_installed
    describe registry_key('HKLM:\\System\\CurrentControlSet\\Control\\SecurePipeServers\\Winreg\\AllowedPaths') do
      it { should exist }
      it { should have_property 'Machine' }
      its('Machine') { should eq '{System\\CurrentControlSet\\Control\\Print\\Printers,System\\CurrentControlSet\\Services\\Eventlog,Software\\Microsoft\\OLAP Server,Software\\Microsoft\\Windows NT\\CurrentVersion\\Print,Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows,System\\CurrentControlSet\\Control\\ContentIndex,System\\CurrentControlSet\\Control\\Terminal Server,System\\CurrentControlSet\\Control\\Terminal Server\\UserConfig,System\\CurrentControlSet\\Control\\Terminal Server\\DefaultUserConfiguration,Software\\Microsoft\\Windows NT\\CurrentVersion\\Perflib,System\\CurrentControlSet\\Services\\SysmonLog,System\\CurrentControlSet\\Services\\WINS}' }
    end
  elsif !wins_installed && ad_cert_installed
    describe registry_key('HKLM:\\System\\CurrentControlSet\\Control\\SecurePipeServers\\Winreg\\AllowedPaths') do
      it { should exist }
      it { should have_property 'Machine' }
      its('Machine') { should eq '{System\\CurrentControlSet\\Control\\Print\\Printers,System\\CurrentControlSet\\Services\\Eventlog,Software\\Microsoft\\OLAP Server,Software\\Microsoft\\Windows NT\\CurrentVersion\\Print,Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows,System\\CurrentControlSet\\Control\\ContentIndex,System\\CurrentControlSet\\Control\\Terminal Server,System\\CurrentControlSet\\Control\\Terminal Server\\UserConfig,System\\CurrentControlSet\\Control\\Terminal Server\\DefaultUserConfiguration,Software\\Microsoft\\Windows NT\\CurrentVersion\\Perflib,System\\CurrentControlSet\\Services\\SysmonLog,System\\CurrentControlSet\\Services\\CertSvc}' }
    end
  elsif wins_installed && ad_cert_installed
    describe registry_key('HKLM:\\System\\CurrentControlSet\\Control\\SecurePipeServers\\Winreg\\AllowedPaths') do
      it { should exist }
      it { should have_property 'Machine' }
      its('Machine') { should eq '{System\\CurrentControlSet\\Control\\Print\\Printers,System\\CurrentControlSet\\Services\\Eventlog,Software\\Microsoft\\OLAP Server,Software\\Microsoft\\Windows NT\\CurrentVersion\\Print,Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows,System\\CurrentControlSet\\Control\\ContentIndex,System\\CurrentControlSet\\Control\\Terminal Server,System\\CurrentControlSet\\Control\\Terminal Server\\UserConfig,System\\CurrentControlSet\\Control\\Terminal Server\\DefaultUserConfiguration,Software\\Microsoft\\Windows NT\\CurrentVersion\\Perflib,System\\CurrentControlSet\\Services\\SysmonLog,System\\CurrentControlSet\\Services\\CertSvc,System\\CurrentControlSet\\Services\\WINS}' }
    end
  end
end

control 'windows-094' do
  title 'Ensure \'Network access: Restrict anonymous access to Named Pipes and Shares\' is set to \'Enabled\''
  desc 'When enabled, this policy setting restricts anonymous access to only those shares and pipes that are named in the Network access: Named pipes that can be accessed anonymously and Network access: Shares that can be accessed anonymously settings. This policy setting controls null session access to shares on your computers by adding RestrictNullSessAccess with the value 1 in the HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters
  registry key. This registry value toggles null session shares on or off to control whether the server service restricts unauthenticated clients\' access to named resources.
  The recommended state for this setting is: Enabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.10.9'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.10.10'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanManServer\\Parameters') do
    it { should exist }
    it { should have_property 'RestrictNullSessAccess' }
    its('RestrictNullSessAccess') { should eq 1 }
  end
end

control 'windows-095' do
  title 'Ensure \'Network access: Restrict clients allowed to make remote calls to SAM\' is set to \'Administrators: Remote Access: Allow\''
  desc 'This policy setting allows you to restrict remote RPC connections to SAM.

  The recommended state for this setting is: Administrators: Remote Access: Allow.

  Note: A Windows 10 R1607, Server 2016 or newer OS is required to access and set this value in Group Policy.'
  impact 1.0
  tag 'windows': %w[2016 2019]
  tag 'profile': ['Member Server']
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.10.11'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('Only for Windows Server 2016, 2019 and if attribute(\'ms_or_dc\') is set to MS') do
    (((os[:name].include? '2016') || (os[:name].include? '2019')) && attribute('ms_or_dc') == 'MS')
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa') do
    it { should have_property 'restrictremotesam' }
    its('restrictremotesam') { should eq 'O:BAG:BAD:(A;;RC;;;BA)' }
  end
end

control 'windows-096' do
  title 'Ensure \'Network access: Shares that can be accessed anonymously\' is set to \'None\''
  desc 'This policy setting determines which network shares can be accessed by anonymous users. The default configuration for this policy setting has little effect because all users have to be authenticated before they can access shared resources on the server.

  The recommended state for this setting is: <blank> (i.e. None).'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.10.10'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.10.12'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanManServer\\Parameters') do
    it { should exist }
    it { should have_property 'NullSessionShares' }
    its('NullSessionShares') { should eq '' }
  end
end

control 'windows-097' do
  title 'Ensure \'Network access: Sharing and security model for local accounts\' is set to \'Classic - local users authenticate as themselves\''
  desc 'This policy setting determines how network logons that use local accounts are authenticated. The Classic option allows precise control over access to resources, including the ability to assign different types of access to different users for the same resource. The Guest only option allows you to treat all users equally. In this context, all users authenticate as Guest only to receive the same access level to a given resource.

  The recommended state for this setting is: Classic - local users authenticate as themselves.

  Note: This setting does not affect interactive logons that are performed remotely by using such services as Telnet or Remote Desktop Services (formerly called Terminal Services).'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.10.11'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.10.13'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M3', 'Sichere Administration'] # FIXME: check Baustein

  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa') do
    it { should exist }
    it { should have_property 'ForceGuest' }
    its('ForceGuest') { should eq 0 }
  end
end

control 'windows-098' do
  title 'Ensure \'Network security: Allow Local System to use computer identity for NTLM\' is set to \'Enabled\''
  desc 'This policy setting determines whether Local System services that use Negotiate when reverting to NTLM authentication can use the computer identity. This policy is supported on at least Windows 7 or Windows Server 2008 R2.

  The recommended state for this setting is: Enabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.11.1'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.11.1'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa') do
    it { should exist }
    it { should have_property 'UseMachineId' }
    its('UseMachineId') { should eq 1 }
  end
end

control 'windows-099' do
  title 'Ensure \'Network security: Allow LocalSystem NULL session fallback\' is set to \'Disabled\''
  desc 'This policy setting determines whether NTLM is allowed to fall back to a NULL session when used with LocalSystem.

  The recommended state for this setting is: Disabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.11.2'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.11.2'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\MSV1_0') do
    it { should exist }
    it { should have_property 'AllowNullSessionFallback' }
    its('AllowNullSessionFallback') { should eq 0 }
  end
end

control 'windows-100' do
  title 'Ensure \'Network Security: Allow PKU2U authentication requests to this computer to use online identities\' is set to \'Disabled\''
  desc 'This setting determines if online identities are able to authenticate to this computer.

  The Public Key Cryptography Based User-to-User (PKU2U) protocol introduced in Windows 7 and Windows Server 2008 R2 is implemented as a security support provider (SSP). The SSP enables peer-to-peer authentication, particularly through the Windows 7 media and file sharing feature called Homegroup, which permits sharing between computers that are not members of a domain.

  With PKU2U, a new extension was introduced to the Negotiate authentication package, Spnego.dll. In previous versions of Windows, Negotiate decided whether to use Kerberos or NTLM for authentication. The extension SSP for Negotiate, Negoexts.dll, which is treated as an authentication protocol by Windows, supports Microsoft SSPs including PKU2U.

  When computers are configured to accept authentication requests by using online IDs, Negoexts.dll calls the PKU2U SSP on the computer that is used to log on. The PKU2U SSP obtains a local certificate and exchanges the policy between the peer computers. When validated on the peer computer, the certificate within the metadata is sent to the logon peer for validation and associates the user\'s certificate to a security token and the logon process completes.

  The recommended state for this setting is: Disabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.11.3'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.11.3'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\pku2u') do
    it { should exist }
    it { should have_property 'AllowOnlineID' }
    its('AllowOnlineID') { should eq 0 }
  end
end

control 'windows-101' do
  title 'Ensure \'Network security: Configure encryption types allowed for Kerberos\' is set to \'RC4_HMAC_MD5, AES128_HMAC_SHA1, AES256_HMAC_SHA1, Future encryption types\''
  desc 'This policy setting allows you to set the encryption types that Kerberos is allowed to use.

  The recommended state for this setting is: RC4_HMAC_MD5, AES128_HMAC_SHA1, AES256_HMAC_SHA1, Future encryption types.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.11.4'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.11.4'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Kerberos\\Parameters') do
    it { should exist }
    it { should have_property 'SupportedEncryptionTypes' }
    its('SupportedEncryptionTypes') { should eq 2_147_483_644 }
  end
end

control 'windows-102' do
  title 'Ensure \'Network security: Do not store LAN Manager hash value on next password change\' is set to \'Enabled\''
  desc 'This policy setting determines whether the LAN Manager (LM) hash value for the new password is stored when the password is changed. The LM hash is relatively weak and prone to attack compared to the cryptographically stronger Microsoft Windows NT hash. Since LM hashes are stored on the local computer in the security database, passwords can then be easily compromised if the database is attacked.

  **Note:** Older operating systems and some third-party applications may fail when this policy setting is enabled. Also, note that the password will need to be changed on all accounts after you enable this setting to gain the proper benefit.

  The recommended state for this setting is: Enabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.11.5'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.11.5'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Lsa') do
    it { should exist }
    it { should have_property 'NoLMHash' }
    its('NoLMHash') { should eq 1 }
  end
end

control 'windows-103' do
  title 'Ensure \'Network security: Force logoff when logon hours expire\' is set to \'Enabled\''
  desc 'This policy setting determines whether to disconnect users who are connected to the local computer outside their user account\'s valid logon hours. This setting affects the Server Message Block (SMB) component. If you enable this policy setting you should also enable **Microsoft network server: Disconnect clients when logon hours expire** (Rule 2.3.9.4).

  The recommended state for this setting is: Enabled.

  Rationale: If this setting is disabled, a user could remain connected to the computer outside of their allotted logon hours.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.11.6'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.11.6'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\LanManServer\\Parameters') do
    it { should exist }
    it { should have_property 'EnableForcedLogOff' }
    its('EnableForcedLogOff') { should eq 1 }
  end
end

control 'windows-104' do
  title 'Ensure \'Network security: LAN Manager authentication level\' is set to \'Send NTLMv2 response only. Refuse LM\''
  desc 'LAN Manager (LM) was a family of early Microsoft client/server software (predating Windows NT) that allowed users to link personal computers together on a single network. LM network capabilities included transparent file and print sharing, user security features, and network administration tools. In Active Directory domains, the Kerberos protocol is the default authentication protocol. However, if the Kerberos protocol is not negotiated for some reason, Active Directory will use LM, NTLM, or NTLMv2. LAN Manager authentication includes the LM, NTLM, and NTLM version 2 (NTLMv2) variants, and is the protocol that is used to authenticate all Windows clients when they perform the following operations:

  * Join a domain
  * Authenticate between Active Directory forests
  * Authenticate to down-level domains
  * Authenticate to computers that do not run Windows 2000, Windows Server 2003, or Windows XP
  * Authenticate to computers that are not in the domain
  The Network security: LAN Manager authentication level setting determines which challenge/response authentication protocol is used for network logons. This choice affects the level of authentication protocol used by clients, the level of session security negotiated, and the level of authentication accepted by servers.

  The recommended state for this setting is: Send NTLMv2 response only. Refuse LM  NTLM.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.11.7'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.11.7'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M3', 'Sichere Administration'] # FIXME: check Baustein
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Lsa') do
    it { should exist }
    it { should have_property 'LmCompatibilityLevel' }
    its('LmCompatibilityLevel') { should eq 5 }
  end
end

control 'windows-105' do
  title 'Ensure \'Network security: LDAP client signing requirements\' is set to \'Negotiate signing\' or higher\''
  desc 'This policy setting determines the level of data signing that is requested on behalf of clients that issue LDAP BIND requests.

  **Note:** This policy setting does not have any impact on LDAP simple bind (ldap_simple_bind) or LDAP simple bind through SSL (ldap_simple_bind_s). No Microsoft LDAP clients that are included with Windows XP Professional use ldap_simple_bind or ldap_simple_bind_s to communicate with a domain controller.

  The recommended state for this setting is: Negotiate signing. Configuring this setting to Require signing also conforms with the benchmark.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.11.8'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.11.8'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\LDAP') do
    it { should exist }
    it { should have_property 'LDAPClientIntegrity' }
    its('LDAPClientIntegrity') { should eq 1 }
  end
end

control 'windows-106' do
  title 'Ensure \'Network security: Minimum session security for NTLM SSP based (including secure RPC) clients\' is set to \'Require NTLMv2 session security, Require 128-bit encryption\''
  desc 'This policy setting determines which behaviors are allowed by clients for applications using the NTLM Security Support Provider (SSP). The SSP Interface (SSPI) is used by applications that need authentication services. The setting does not modify how the authentication sequence works but instead require certain behaviors in applications that use the SSPI.

  The recommended state for this setting is: Require NTLMv2 session security, Require 128-bit encryption. **Note:** These values are dependent on the **Network security: LAN Manager Authentication Level** security setting value.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.11.9'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.11.9'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\MSV1_0') do
    it { should exist }
    it { should have_property 'NTLMMinClientSec' }
    its('NTLMMinClientSec') { should eq 536870912 }
  end
end

control 'windows-107' do
  title 'Ensure \'Network security: Minimum session security for NTLM SSP based (including secure RPC) servers\' is set to \'Require NTLMv2 session security, Require 128-bit encryption\''
  desc ' This policy setting determines which behaviors are allowed by servers for applications using the NTLM Security Support Provider (SSP). The SSP Interface (SSPI) is used by applications that need authentication services. The setting does not modify how the authentication sequence works but instead require certain behaviors in applications that use the SSPI.

  The recommended state for this setting is: Require NTLMv2 session security, Require 128-bit encryption. **Note:** These values are dependent on the **Network security: LAN Manager Authentication Level** security setting value.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.11.10'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.11.10'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\MSV1_0') do
    it { should exist }
    it { should have_property 'NTLMMinServerSec' }
    its('NTLMMinServerSec') { should eq 536870912 }
  end
end

control 'windows-108' do
  title 'Ensure \'Shutdown: Allow system to be shut down without having to log on\' is set to \'Disabled\''
  desc 'This policy setting determines whether a computer can be shut down when a user is not logged on. If this policy setting is enabled, the shutdown command is available on the Windows logon screen. It is recommended to disable this policy setting to restrict the ability to shut down the computer to users with credentials on the system.

  The recommended state for this setting is: Disabled. **Note:** In Server 2008 R2 and older versions, this setting had no impact on Remote Desktop (RDP) / Terminal Services sessions - it only affected the local console. However, Microsoft changed the behavior in Windows Server 2012 (non-R2) and above, where if set to Enabled, RDP sessions are also allowed to shut down or restart the server.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.13.1'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.13.1'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System') do
    it { should exist }
    it { should have_property 'ShutdownWithoutLogon' }
    its('ShutdownWithoutLogon') { should eq 0 }
  end
end

control 'windows-109' do
  title 'Ensure \'System objects: Require case insensitivity for non-Windows subsystems\' is set to \'Enabled\''
  desc 'This policy setting determines whether case insensitivity is enforced for all subsystems. The Microsoft Win32 subsystem is case insensitive. However, the kernel supports case sensitivity for other subsystems, such as the Portable Operating System Interface for UNIX (POSIX). Because Windows is case insensitive (but the POSIX subsystem will support case sensitivity), failure to enforce this policy setting makes it possible for a user of the POSIX subsystem to create a file with the same name as another file by using mixed case to label it. Such a situation can block access to these files by another user who uses typical Win32 tools, because only one of the files will be available.

  The recommended state for this setting is: Enabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.15.1'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.15.1'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Session Manager\\Kernel') do
    it { should exist }
    it { should have_property 'ObCaseInsensitive' }
    its('ObCaseInsensitive') { should eq 1 }
  end
end

control 'windows-110' do
  title 'Ensure \'System objects: Strengthen default permissions of internal system objects (e.g. Symbolic Links)\' is set to \'Enabled\''
  desc 'This policy setting determines the strength of the default discretionary access control list (DACL) for objects. Active Directory maintains a global list of shared system resources, such as DOS device names, mutexes, and semaphores. In this way, objects can be located and shared among processes. Each type of object is created with a default DACL that specifies who can access the objects and what permissions are granted.

  The recommended state for this setting is: Enabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.15.2'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.15.2'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Session Manager') do
    it { should exist }
    it { should have_property 'ProtectionMode' }
    its('ProtectionMode') { should eq 1 }
  end
end

control 'windows-111' do
  title 'Ensure \'User Account Control: Admin Approval Mode for the Built-in Administrator account\' is set to \'Enabled\''
  desc 'This policy setting controls the behavior of Admin Approval Mode for the built-in Administrator account.

  The recommended state for this setting is: Enabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.17.1'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.17.1'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System') do
    it { should exist }
    it { should have_property 'FilterAdministratorToken' }
    its('FilterAdministratorToken') { should eq 1 }
  end
end

control 'windows-112' do
  title 'Ensure \'User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop\' is set to \'Disabled\''
  desc 'This policy setting controls whether User Interface Accessibility (UIAccess or UIA) programs can automatically disable the secure desktop for elevation prompts used by a standard user.

  The recommended state for this setting is: Disabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.17.2'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.17.2'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M3', 'Sichere Administration', 'SYS.1.2.2.M6', 'Sichere Authentisierung und Autorisierung']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System') do
    it { should exist }
    it { should have_property 'EnableUIADesktopToggle' }
    its('EnableUIADesktopToggle') { should eq 0 }
  end
end

control 'windows-113' do
  title 'Ensure \'User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode\' is set to \'Prompt for consent on the secure desktop\''
  desc 'This policy setting controls the behavior of the elevation prompt for administrators.

  The recommended state for this setting is: Prompt for consent on the secure desktop.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.17.3'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.17.3'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M3', 'Sichere Administration', 'SYS.1.2.2.M6', 'Sichere Authentisierung und Autorisierung']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System') do
    it { should exist }
    it { should have_property 'ConsentPromptBehaviorAdmin' }
    its('ConsentPromptBehaviorAdmin') { should eq 2 }
  end
end

control 'windows-114' do
  title 'Ensure \'User Account Control: Behavior of the elevation prompt for standard users\' is set to \'Automatically deny elevation requests\''
  desc 'This policy setting controls the behavior of the elevation prompt for standard users.

  The recommended state for this setting is: Automatically deny elevation requests.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.17.4'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.17.4'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M3', 'Sichere Administration', 'SYS.1.2.2.M6', 'Sichere Authentisierung und Autorisierung']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System') do
    it { should exist }
    it { should have_property 'ConsentPromptBehaviorUser' }
    its('ConsentPromptBehaviorUser') { should eq 0 }
  end
end

control 'windows-115' do
  title 'Ensure \'User Account Control: Detect application installations and prompt for elevation\' is set to \'Enabled\''
  desc 'This policy setting controls the behavior of application installation detection for the computer.

  The recommended state for this setting is: Enabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.17.5'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.17.5'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M3', 'Sichere Administration', 'SYS.1.2.2.M6', 'Sichere Authentisierung und Autorisierung']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System') do
    it { should exist }
    it { should have_property 'EnableInstallerDetection' }
    its('EnableInstallerDetection') { should eq 1 }
  end
end

control 'windows-116' do
  title 'Ensure \'User Account Control: Only elevate UIAccess applications that are installed in secure locations\' is set to \'Enabled\''
  desc 'This policy setting controls whether applications that request to run with a User Interface Accessibility (UIAccess) integrity level must reside in a secure location in the file system. Secure locations are limited to the following: - &#x2026;\\Program Files\\, including subfolders - &#x2026;\\Windows\\system32\\ - &#x2026;\\Program Files (x86)\\, including subfolders for 64-bit versions of Windows

  **Note:** Windows enforces a public key infrastructure (PKI) signature check on any interactive application that requests to run with a UIAccess integrity level regardless of the state of this security setting.

  The recommended state for this setting is: Enabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.17.6'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.17.6'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M3', 'Sichere Administration', 'SYS.1.2.2.M6', 'Sichere Authentisierung und Autorisierung']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System') do
    it { should exist }
    it { should have_property 'EnableSecureUIAPaths' }
    its('EnableSecureUIAPaths') { should eq 1 }
  end
end

control 'windows-117' do
  title 'Ensure \'User Account Control: Run all administrators in Admin Approval Mode\' is set to \'Enabled\''
  desc 'This policy setting controls the behavior of all User Account Control (UAC) policy settings for the computer. If you change this policy setting, you must restart your computer.

  The recommended state for this setting is: Enabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.17.7'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.17.7'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M3', 'Sichere Administration', 'SYS.1.2.2.M6', 'Sichere Authentisierung und Autorisierung']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System') do
    it { should exist }
    it { should have_property 'EnableLUA' }
    its('EnableLUA') { should eq 1 }
  end
end

control 'windows-118' do
  title 'Ensure \'User Account Control: Switch to the secure desktop when prompting for elevation\' is set to \'Enabled\''
  desc 'This policy setting controls whether the elevation request prompt is displayed on the interactive user\'s desktop or the secure desktop.

  The recommended state for this setting is: Enabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.17.8'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.17.8'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M3', 'Sichere Administration', 'SYS.1.2.2.M6', 'Sichere Authentisierung und Autorisierung']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System') do
    it { should exist }
    it { should have_property 'PromptOnSecureDesktop' }
    its('PromptOnSecureDesktop') { should eq 1 }
  end
end

control 'windows-119' do
  title 'Ensure \'User Account Control: Virtualize file and registry write failures to per-user locations\' is set to \'Enabled\''
  desc 'This policy setting controls whether application write failures are redirected to defined registry and file system locations. This policy setting mitigates applications that run as administrator and write run-time application data to: - %ProgramFiles%, - %Windir%, - %Windir%\\system32, or - HKEY_LOCAL_MACHINE\\Software.

  The recommended state for this setting is: Enabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.17.9'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.17.9'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M3', 'Sichere Administration', 'SYS.1.2.2.M6', 'Sichere Authentisierung und Autorisierung']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System') do
    it { should exist }
    it { should have_property 'EnableVirtualization' }
    its('EnableVirtualization') { should eq 1 }
  end
end

control 'windows-120' do
  title 'Ensure \'Windows Firewall: Domain: Firewall state\' is set to \'On (recommended)\''
  desc 'Select On (recommended) to have Windows Firewall with Advanced Security use the settings for this profile to filter network traffic. If you select Off, Windows Firewall with Advanced Security will not use any of the firewall rules or connection security rules for this profile.

  The recommended state for this setting is: On (recommended).'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '9.1.1'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '9.1.1'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M3', 'Sichere Administration', 'SYS.1.2.2.M9', 'Lokale Kommunikationsfilterung (CI)']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\WindowsFirewall\\DomainProfile') do
    it { should exist }
    it { should have_property 'EnableFirewall' }
    its('EnableFirewall') { should eq 1 }
  end
end

control 'windows-121' do
  title 'Ensure \'Windows Firewall: Domain: Inbound connections\' is set to \'Block (default)\''
  desc 'This setting determines the behavior for inbound connections that do not match an inbound firewall rule.

  The recommended state for this setting is: Block (default).'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '9.1.2'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '9.1.2'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M3', 'Sichere Administration', 'SYS.1.2.2.M9', 'Lokale Kommunikationsfilterung (CI)']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\WindowsFirewall\\DomainProfile') do
    it { should exist }
    it { should have_property 'DefaultInboundAction' }
    its('DefaultInboundAction') { should eq 1 }
  end
end

control 'windows-122' do
  title 'Ensure \'Windows Firewall: Domain: Outbound connections\' is set to \'Allow (default)\''
  desc 'This setting determines the behavior for outbound connections that do not match an outbound firewall rule.

  The recommended state for this setting is: Allow (default).'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '9.1.3'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '9.1.3'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M3', 'Sichere Administration', 'SYS.1.2.2.M9', 'Lokale Kommunikationsfilterung (CI)']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\WindowsFirewall\\DomainProfile') do
    it { should exist }
    it { should have_property 'DefaultOutboundAction' }
    its('DefaultOutboundAction') { should eq 0 }
  end
end

control 'windows-123' do
  title 'Ensure \'Windows Firewall: Domain: Settings: Display a notification\' is set to \'No\''
  desc 'Select this option to have Windows Firewall with Advanced Security display notifications to the user when a program is blocked from receiving inbound connections.

  The recommended state for this setting is: No.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '9.1.4'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '9.1.4'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M3', 'Sichere Administration', 'SYS.1.2.2.M9', 'Lokale Kommunikationsfilterung (CI)']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\WindowsFirewall\\DomainProfile') do
    it { should exist }
    it { should have_property 'DisableNotifications' }
    its('DisableNotifications') { should eq 1 }
  end
end

control 'windows-124' do
  title 'Ensure \'Windows Firewall: Domain: Logging: Name\' is set to \'%SYSTEMROOT%\\System32\\logfiles\\firewall\\domainfw.log\''
  desc ' Use this option to specify the path and name of the file in which Windows Firewall will write its log information.

  The recommended state for this setting is: %SYSTEMROOT%\\System32\\logfiles\\firewall\\domainfw.log.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '9.1.5'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '9.1.5'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration', 'SYS.1.2.2.M9', 'Lokale Kommunikationsfilterung (CI)']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\WindowsFirewall\\DomainProfile\\Logging') do
    it { should exist }
    it { should have_property 'LogFilePath' }
    its('LogFilePath') { should eq '%SYSTEMROOT%\\System32\\logfiles\\firewall\\domainfw.log'.downcase }
  end
end

control 'windows-125' do
  title 'Ensure \'Windows Firewall: Domain: Logging: Size limit (KB)\' is set to \'16,384 KB or greater\''
  desc 'Use this option to specify the size limit of the file in which Windows Firewall will write its log information.

  The recommended state for this setting is: 16,384 KB or greater.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '9.1.6'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '9.1.6'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration', 'SYS.1.2.2.M9', 'Lokale Kommunikationsfilterung (CI)']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\WindowsFirewall\\DomainProfile\\Logging') do
    it { should exist }
    it { should have_property 'LogFileSize' }
    its('LogFileSize') { should be >= 16384 }
  end
end

control 'windows-126' do
  title 'Ensure \'Windows Firewall: Domain: Logging: Log dropped packets\' is set to \'Yes\''
  desc 'Use this option to log when Windows Firewall with Advanced Security discards an inbound packet for any reason. The log records why and when the packet was dropped. Look for entries with the word DROP in the action column of the log.

  The recommended state for this setting is: Yes.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '9.1.7'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '9.1.7'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration', 'SYS.1.2.2.M9', 'Lokale Kommunikationsfilterung (CI)']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\WindowsFirewall\\DomainProfile\\Logging') do
    it { should exist }
    it { should have_property 'LogDroppedPackets' }
    its('LogDroppedPackets') { should eq 1 }
  end
end

control 'windows-127' do
  title 'Ensure \'Windows Firewall: Domain: Logging: Log successful connections\' is set to \'Yes\''
  desc 'Use this option to log when Windows Firewall with Advanced Security allows an inbound connection. The log records why and when the connection was formed. Look for entries with the word ALLOW in the action column of the log.

  The recommended state for this setting is: Yes.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '9.1.8'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '9.1.8'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration', 'SYS.1.2.2.M9', 'Lokale Kommunikationsfilterung (CI)']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\WindowsFirewall\\DomainProfile\\Logging') do
    it { should exist }
    it { should have_property 'LogSuccessfulConnections' }
    its('LogSuccessfulConnections') { should eq 1 }
  end
end

control 'windows-128' do
  title 'Ensure \'Windows Firewall: Private: Firewall state\' is set to \'On (recommended)\''
  desc 'Select On (recommended) to have Windows Firewall with Advanced Security use the settings for this profile to filter network traffic. If you select Off, Windows Firewall with Advanced Security will not use any of the firewall rules or connection security rules for this profile.

  The recommended state for this setting is: On (recommended).'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '9.2.1'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '9.2.1'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration', 'SYS.1.2.2.M9', 'Lokale Kommunikationsfilterung (CI)']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\WindowsFirewall\\PrivateProfile') do
    it { should exist }
    it { should have_property 'EnableFirewall' }
    its('EnableFirewall') { should eq 1 }
  end
end

control 'windows-129' do
  title 'Ensure \'Windows Firewall: Private: Inbound connections\' is set to \'Block (default)\''
  desc 'This setting determines the behavior for inbound connections that do not match an inbound firewall rule.

  The recommended state for this setting is: Block (default).'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '9.2.2'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '9.2.2'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration', 'SYS.1.2.2.M9', 'Lokale Kommunikationsfilterung (CI)']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\WindowsFirewall\\PrivateProfile') do
    it { should exist }
    it { should have_property 'DefaultInboundAction' }
    its('DefaultInboundAction') { should eq 1 }
  end
end

control 'windows-130' do
  title 'Ensure \'Windows Firewall: Private: Outbound connections\' is set to \'Allow (default)\''
  desc 'This setting determines the behavior for outbound connections that do not match an outbound firewall rule.

  The recommended state for this setting is: Allow (default).'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '9.2.3'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '9.2.3'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration', 'SYS.1.2.2.M9', 'Lokale Kommunikationsfilterung (CI)']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\WindowsFirewall\\PrivateProfile') do
    it { should exist }
    it { should have_property 'DefaultOutboundAction' }
    its('DefaultOutboundAction') { should eq 0 }
  end
end

control 'windows-131' do
  title 'Ensure \'Windows Firewall: Private: Settings: Display a notification\' is set to \'No\''
  desc 'Select this option to have Windows Firewall with Advanced Security display notifications to the user when a program is blocked from receiving inbound connections.

  The recommended state for this setting is: No.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '9.2.4'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '9.2.4'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration', 'SYS.1.2.2.M9', 'Lokale Kommunikationsfilterung (CI)']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\WindowsFirewall\\PrivateProfile') do
    it { should exist }
    it { should have_property 'DisableNotifications' }
    its('DisableNotifications') { should eq 1 }
  end
end

control 'windows-132' do
  title 'Ensure \'Windows Firewall: Private: Logging: Name\' is set to \'%SYSTEMROOT%\System32\logfiles\firewall\privatefw.log\''
  desc 'This setting controls whether local administrators are allowed to create local firewall rules that apply together with firewall rules configured by Group Policy.

  The recommended state for this setting is: Yes (default).'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '9.2.5'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '9.2.5'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration', 'SYS.1.2.2.M9', 'Lokale Kommunikationsfilterung (CI)']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\WindowsFirewall\\PrivateProfile\\Logging') do
    it { should exist }
    it { should have_property 'LogFilePath' }
    its('LogFilePath') { should eq '%SYSTEMROOT%\\System32\\logfiles\\firewall\\privatefw.log'.downcase }
  end
end

control 'windows-133' do
  title 'Ensure \'Windows Firewall: Private: Logging: Size limit (KB)\' is set to \'16,384 KB or greater\''
  desc 'Use this option to specify the size limit of the file in which Windows Firewall will write its log information.

  The recommended state for this setting is: 16,384 KB or greater.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '9.2.6'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '9.2.6'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration', 'SYS.1.2.2.M9', 'Lokale Kommunikationsfilterung (CI)']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\WindowsFirewall\\PrivateProfile\\Logging') do
    it { should exist }
    it { should have_property 'LogFileSize' }
    its('LogFileSize') { should be >= 16384 }
  end
end

control 'windows-134' do
  title 'Ensure \'Windows Firewall: Private: Logging: Log dropped packets\' is set to \'Yes\''
  desc 'Use this option to log when Windows Firewall with Advanced Security discards an inbound packet for any reason. The log records why and when the packet was dropped. Look for entries with the word DROP in the action column of the log.

  The recommended state for this setting is: Yes.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '9.2.7'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '9.2.7'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration', 'SYS.1.2.2.M9', 'Lokale Kommunikationsfilterung (CI)']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\WindowsFirewall\\PrivateProfile\\Logging') do
    it { should exist }
    it { should have_property 'LogDroppedPackets' }
    its('LogDroppedPackets') { should eq 1 }
  end
end

control 'windows-135' do
  title 'Ensure \'Windows Firewall: Private: Logging: Log successful connections\' is set to \'Yes\''
  desc 'Use this option to log when Windows Firewall with Advanced Security allows an inbound connection. The log records why and when the connection was formed. Look for entries with the word ALLOW in the action column of the log.

  The recommended state for this setting is: Yes.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '9.2.8'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '9.2.8'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration', 'SYS.1.2.2.M9', 'Lokale Kommunikationsfilterung (CI)']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\WindowsFirewall\\PrivateProfile\\Logging') do
    it { should exist }
    it { should have_property 'LogSuccessfulConnections' }
    its('LogSuccessfulConnections') { should eq 1 }
  end
end

control 'windows-136' do
  title 'Ensure \'Windows Firewall: Public: Firewall state\' is set to \'On (recommended)\''
  desc 'Select On (recommended) to have Windows Firewall with Advanced Security use the settings for this profile to filter network traffic. If you select Off, Windows Firewall with Advanced Security will not use any of the firewall rules or connection security rules for this profile.

  The recommended state for this setting is: On (recommended).'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '9.3.1'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '9.3.1'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration', 'SYS.1.2.2.M9', 'Lokale Kommunikationsfilterung (CI)']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\WindowsFirewall\\PublicProfile') do
    it { should exist }
    it { should have_property 'EnableFirewall' }
    its('EnableFirewall') { should eq 1 }
  end
end

control 'windows-137' do
  title 'Ensure \'Windows Firewall: Public: Inbound connections\' is set to \'Block (default)\''
  desc 'This setting determines the behavior for inbound connections that do not match an inbound firewall rule.

  The recommended state for this setting is: Block (default).'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '9.3.2'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '9.3.2'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration', 'SYS.1.2.2.M9', 'Lokale Kommunikationsfilterung (CI)']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\WindowsFirewall\\PublicProfile') do
    it { should exist }
    it { should have_property 'DefaultInboundAction' }
    its('DefaultInboundAction') { should eq 1 }
  end
end

control 'windows-138' do
  title 'Ensure \'Windows Firewall: Public: Outbound connections\' is set to \'Allow (default)\''
  desc 'This setting determines the behavior for outbound connections that do not match an outbound firewall rule.

  The recommended state for this setting is: Allow (default).

  **Note:** If you set Outbound connections to Block and then deploy the firewall policy by using a GPO, computers that receive the GPO settings cannot receive subsequent Group Policy updates unless you create and deploy an outbound rule that enables Group Policy to work. Predefined rules for Core Networking include outbound rules that enable Group Policy to work. Ensure that these outbound rules are active, and thoroughly test firewall profiles before deploying.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '9.3.3'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '9.3.3'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration', 'SYS.1.2.2.M9', 'Lokale Kommunikationsfilterung (CI)']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\WindowsFirewall\\PublicProfile') do
    it { should exist }
    it { should have_property 'DefaultOutboundAction' }
    its('DefaultOutboundAction') { should eq 0 }
  end
end

control 'windows-139' do
  title 'Ensure \'Windows Firewall: Public: Settings: Display a notification\' is set to \'Yes\''
  desc 'Select this option to have Windows Firewall with Advanced Security display notifications to the user when a program is blocked from receiving inbound connections.

  The recommended state for this setting is: Yes.

  **Note:** When the Apply local firewall rules setting is configured to Yes, it is also recommended to also configure the Display a notification setting to Yes. Otherwise, users will not receive messages that ask if they want to unblock a restricted inbound connection.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '9.3.4'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '9.3.4'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration', 'SYS.1.2.2.M9', 'Lokale Kommunikationsfilterung (CI)']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\WindowsFirewall\\PublicProfile') do
    it { should exist }
    it { should have_property 'DisableNotifications' }
    its('DisableNotifications') { should eq 0 }
  end
end

control 'windows-140' do
  title 'Ensure \'Windows Firewall: Public: Settings: Apply local firewall rules\' is set to \'No\''
  desc 'This setting controls whether local administrators are allowed to create local firewall rules that apply together with firewall rules configured by Group Policy.

  The recommended state for this setting is: No.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '9.3.5'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '9.3.5'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration', 'SYS.1.2.2.M9', 'Lokale Kommunikationsfilterung (CI)']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\WindowsFirewall\\PublicProfile') do
    it { should exist }
    it { should have_property 'AllowLocalPolicyMerge' }
    its('AllowLocalPolicyMerge') { should eq 0 }
  end
end

control 'windows-141' do
  title 'Ensure \'Windows Firewall: Public: Settings: Apply local connection security rules\' is set to \'No\''
  desc 'This setting controls whether local administrators are allowed to create connection security rules that apply together with connection security rules configured by Group Policy.

  The recommended state for this setting is: No.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '9.3.6'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '9.3.6'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration', 'SYS.1.2.2.M9', 'Lokale Kommunikationsfilterung (CI)']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\WindowsFirewall\\PublicProfile') do
    it { should exist }
    it { should have_property 'AllowLocalIPsecPolicyMerge' }
    its('AllowLocalIPsecPolicyMerge') { should eq 0 }
  end
end

control 'windows-142' do
  title 'Ensure \'Windows Firewall: Public: Logging: Name\' is set to \'%SYSTEMROOT%\\System32\\logfiles\\firewall\\publicfw.log\''
  desc 'Use this option to specify the path and name of the file in which Windows Firewall will write its log information.

  The recommended state for this setting is: %SYSTEMROOT%\\System32\\logfiles\\firewall\\publicfw.log.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '9.3.7'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '9.3.7'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration', 'SYS.1.2.2.M9', 'Lokale Kommunikationsfilterung (CI)']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\WindowsFirewall\\PublicProfile\\Logging') do
    it { should exist }
    it { should have_property 'LogFilePath' }
    its('LogFilePath') { should eq '%systemroot%\\system32\\logfiles\\firewall\\publicfw.log'.downcase }
  end
end

control 'windows-143' do
  title 'Ensure \'Windows Firewall: Public: Logging: Size limit (KB)\' is set to \'16,384 KB or greater\''
  desc 'Use this option to specify the size limit of the file in which Windows Firewall will write its log information.

  The recommended state for this setting is: 16,384 KB or greater.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '9.3.8'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '9.3.8'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration', 'SYS.1.2.2.M9', 'Lokale Kommunikationsfilterung (CI)']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\WindowsFirewall\\PublicProfile\\Logging') do
    it { should exist }
    it { should have_property 'LogFileSize' }
    its('LogFileSize') { should be >= 16384 }
  end
end

control 'windows-144' do
  title 'Ensure \'Windows Firewall: Public: Logging: Log dropped packets\' is set to \'Yes\''
  desc 'Use this option to log when Windows Firewall with Advanced Security discards an inbound packet for any reason. The log records why and when the packet was dropped. Look for entries with the word DROP in the action column of the log.

  The recommended state for this setting is: Yes.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '9.3.9'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '9.3.9'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration', 'SYS.1.2.2.M9', 'Lokale Kommunikationsfilterung (CI)']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\WindowsFirewall\\PublicProfile\\Logging') do
    it { should exist }
    it { should have_property 'LogDroppedPackets' }
    its('LogDroppedPackets') { should eq 1 }
  end
end

control 'windows-145' do
  title 'Ensure \'Windows Firewall: Public: Logging: Log successful connections\' is set to \'Yes\''
  desc 'Use this option to log when Windows Firewall with Advanced Security allows an inbound connection. The log records why and when the connection was formed. Look for entries with the word ALLOW in the action column of the log.

  The recommended state for this setting is: Yes.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '9.3.10'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '9.3.10'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration', 'SYS.1.2.2.M9', 'Lokale Kommunikationsfilterung (CI)']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\WindowsFirewall\\PublicProfile\\Logging') do
    it { should exist }
    it { should have_property 'LogSuccessfulConnections' }
    its('LogSuccessfulConnections') { should eq 1 }
  end
end

control 'windows-146' do
  title 'Ensure \'Audit Credential Validation\' is set to \'Success and Failure\''
  desc 'This subcategory reports the results of validation tests on credentials submitted for a user account logon request. These events occur on the computer that is authoritative for the credentials. For domain accounts, the domain controller is authoritative, whereas for local accounts, the local computer is authoritative. In domain environments, most of the Account Logon events occur in the Security log of the domain controllers that are authoritative for the domain accounts. However, these events can occur on other computers in the organization when local accounts are used to log on. Events for this subcategory include:

  * 4774: An account was mapped for logon.
  * 4775: An account could not be mapped for logon.
  * 4776: The domain controller attempted to validate the credentials for an account.
  * 4777: The domain controller failed to validate the credentials for an account.
  The recommended state for this setting is: Success and Failure.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '17.1.1'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '17.1.1'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe audit_policy do
    its('Credential Validation') { should eq 'Success and Failure' }
  end
end

control 'windows-147' do
  title 'Ensure \'Audit Application Group Management\' is set to \'Success and Failure\''
  desc 'This policy setting allows you to audit events generated by changes to application groups such as the following:

  * Application group is created, changed, or deleted.
  * Member is added or removed from an application group.
  Application groups are utilized by Windows Authorization Manager, which is a flexible framework created by Microsoft for integrating role-based access control (RBAC) into applications. More information on Windows Authorization Manager is available at [MSDN - Windows Authorization Manager](https://msdn.microsoft.com/en-us/library/bb897401.aspx).

  The recommended state for this setting is: Success and Failure.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '17.2.1'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '17.2.1'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe audit_policy do
    its('Application Group Management') { should eq 'Success and Failure' }
  end
end

control 'windows-148' do
  title 'Ensure \'Audit Computer Account Management\' is set to \'Success and Failure\''
  desc 'This subcategory reports each event of computer account management, such as when a computer account is created, changed, deleted, renamed, disabled, or enabled. Events for this subcategory include:

  * 4741: A computer account was created.
  * 4742: A computer account was changed.
  * 4743: A computer account was deleted.
  The recommended state for this setting is: Success and Failure.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '17.2.2'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '17.2.2'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe audit_policy do
    its('Computer Account Management') { should eq 'Success and Failure' }
  end
end

control 'windows-149' do
  title 'Ensure \'Audit Distribution Group Management\' is set to \'Success and Failure\' (DC only)\''
  desc 'This subcategory reports each event of distribution group management, such as when a distribution group is created, changed, or deleted or when a member is added to or removed from a distribution group. If you enable this Audit policy setting, administrators can track events to detect malicious, accidental, and authorized creation of group accounts. Events for this subcategory include:

  - 4744: A security-disabled local group was created.
  - 4745: A security-disabled local group was changed.
  - 4746: A member was added to a security-disabled local group.
  - 4747: A member was removed from a security-disabled local group.
  - 4748: A security-disabled local group was deleted.
  - 4749: A security-disabled global group was created.
  - 4750: A security-disabled global group was changed.
  - 4751: A member was added to a security-disabled global group.
  - 4752: A member was removed from a security-disabled global group.
  - 4753: A security-disabled global group was deleted.
  - 4759: A security-disabled universal group was created.
  - 4760: A security-disabled universal group was changed.
  - 4761: A member was added to a security-disabled universal group.
  - 4762: A member was removed from a security-disabled universal group.
  - 4763: A security-disabled universal group was deleted.

  The recommended state for this setting is: Success and Failure.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '17.2.3'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '17.2.3'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('This Control only executes if attribute(\'ms_or_dc\') is set to MS') do
    attribute('ms_or_dc') == 'DC'
  end
  describe audit_policy do
    its('Distribution Group Management') { should eq 'Success and Failure' }
  end
end

control 'windows-150' do
  title 'Ensure \'Audit Other Account Management Events\' is set to \'Success and Failure\''
  desc 'This subcategory reports other account management events. Events for this subcategory include:

  * 4782: The password hash an account was accessed.
  * 4793: The Password Policy Checking API was called.
  The recommended state for this setting is: Success and Failure.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '17.2.4'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '17.2.4'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe audit_policy do
    its('Other Account Management Events') { should eq 'Success and Failure' }
  end
end

control 'windows-151' do
  title 'Ensure \'Audit Security Group Management\' is set to \'Success and Failure\''
  desc 'This subcategory reports each event of security group management, such as when a security group is created, changed, or deleted or when a member is added to or removed from a security group. If you enable this Audit policy setting, administrators can track events to detect malicious, accidental, and authorized creation of security group accounts. Events for this subcategory include:

  * 4727: A security-enabled global group was created.
  * 4728: A member was added to a security-enabled global group.
  * 4729: A member was removed from a security-enabled global group.
  * 4730: A security-enabled global group was deleted.
  * 4731: A security-enabled local group was created.
  * 4732: A member was added to a security-enabled local group.
  * 4733: A member was removed from a security-enabled local group.
  * 4734: A security-enabled local group was deleted.
  * 4735: A security-enabled local group was changed.
  * 4737: A security-enabled global group was changed.
  * 4754: A security-enabled universal group was created.
  * 4755: A security-enabled universal group was changed.
  * 4756: A member was added to a security-enabled universal group.
  * 4757: A member was removed from a security-enabled universal group.
  * 4758: A security-enabled universal group was deleted.
  * 4764: A group\'s type was changed.
  The recommended state for this setting is: Success and Failure.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '17.2.5'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '17.2.5'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe audit_policy do
    its('Security Group Management') { should eq 'Success and Failure' }
  end
end

control 'windows-152' do
  title 'Ensure \'Audit User Account Management\' is set to \'Success and Failure\''
  desc 'This subcategory reports each event of user account management, such as when a user account is created, changed, or deleted; a user account is renamed, disabled, or enabled; or a password is set or changed. If you enable this Audit policy setting, administrators can track events to detect malicious, accidental, and authorized creation of user accounts. Events for this subcategory include:

  * 4720: A user account was created.
  * 4722: A user account was enabled.
  * 4723: An attempt was made to change an account\'s password.
  * 4724: An attempt was made to reset an account\'s password.
  * 4725: A user account was disabled.
  * 4726: A user account was deleted.
  * 4738: A user account was changed.
  * 4740: A user account was locked out.
  * 4765: SID History was added to an account.
  * 4766: An attempt to add SID History to an account failed.
  * 4767: A user account was unlocked.
  * 4780: The ACL was set on accounts which are members of administrators groups.
  * 4781: The name of an account was changed:
  * 4794: An attempt was made to set the Directory Services Restore Mode.
  * 5376: Credential Manager credentials were backed up.
  * 5377: Credential Manager credentials were restored from a backup.
  The recommended state for this setting is: Success and Failure.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '17.2.6'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '17.2.6'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe audit_policy do
    its('User Account Management') { should eq 'Success and Failure' }
  end
end

control 'windows-153' do
  title '(L1) Ensure \'Audit PNP Activity\' is set to \'Success\''
  desc 'This policy setting allows you to audit when plug and play detects an external device.

  The recommended state for this setting is: Success.

  **Note:** A Windows 10, Server 2016 or higher OS is required to access and set this value in Group Policy.'
  impact 1.0
  tag 'windows': %w[2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '17.3.1'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('Only for Windows Server 2016, 2019') do
    ((os[:name].include? '2016') || (os[:name].include? '2019'))
  end
  describe audit_policy do
    its('Plug and Play Events') { should eq 'Success' }
  end
end

control 'windows-154' do
  title 'Ensure \'Audit Process Creation\' is set to \'Success\''
  desc 'This subcategory reports the creation of a process and the name of the program or user that created it. Events for this subcategory include:

  * 4688: A new process has been created.
  * 4696: A primary token was assigned to process.
  Refer to Microsoft Knowledge Base article 947226: [Description of security events in Windows Vista and in Windows Server 2008](https://support.microsoft.com/en-us/kb/947226) for the most recent information about this setting.

  The recommended state for this setting is: Success.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '17.3.1'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '17.3.2'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']

  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe audit_policy do
    its('Process Creation') { should eq 'Success' }
  end
end

control 'windows-156' do
  title 'Ensure \'Audit Directory Service Access\' is set to \'Success and Failure\' (DC only)'
  desc 'This subcategory reports when an AD DS object is accessed. Only objects with SACLs cause audit events to be generated, and only when they are accessed in a manner that matches their SACL. These events are similar to the directory service access events in previous versions of Windows Server. This subcategory applies only to Domain Controllers. Events for this subcategory include:

  * 4662 : An operation was performed on an object.
  The recommended state for this setting is: Success and Failure.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '17.4.1'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '17.4.1'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('This Control only executes if attribute(\'ms_or_dc\') is set to MS') do
    attribute('ms_or_dc') == 'DC'
  end
  describe audit_policy do
    its('Directory Service Access') { should eq 'Success and Failure' }
  end
end

control 'windows-157' do
  title 'Ensure \'Audit Directory Service Changes\' is set to \'Success and Failure\' (DC only)'
  desc 'This subcategory reports changes to objects in Active Directory Domain Services (AD DS). The types of changes that are reported are create, modify, move, and undelete operations that are performed on an object. DS Change auditing, where appropriate, indicates the old and new values of the changed properties of the objects that were changed. Only objects with SACLs cause audit events to be generated, and only when they are accessed in a manner that matches their SACL. Some objects and properties do not cause audit events to be generated due to settings on the object class in the schema. This subcategory applies only to Domain Controllers. Events for this subcategory include:

    * 5136 : A directory service object was modified.
    * 5137 : A directory service object was created.
    * 5138 : A directory service object was undeleted.
    * 5139 : A directory service object was moved.
    The recommended state for this setting is: Success and Failure.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '17.4.2'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '17.4.2'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('This Control only executes if attribute(\'ms_or_dc\') is set to MS') do
    attribute('ms_or_dc') == 'DC'
  end
  describe audit_policy do
    its('Directory Service Changes') { should eq 'Success and Failure' }
  end
end

control 'windows-158' do
  title 'Ensure \'Audit Account Lockout\' is set to \'Success and Failure\''
  desc 'This subcategory reports when a user\'s account is locked out as a result of too many failed logon attempts. Events for this subcategory include:

  * 4625: An account failed to log on.
  The recommended state for this setting is: Success and Failure.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '17.5.1'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '17.5.1'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe audit_policy do
    its('Account Lockout') { should eq 'Success and Failure' }
  end
end

control 'windows-159' do
  title 'Ensure \'Audit Group Membership\' is set to \'Success\''
  desc 'This policy allows you to audit the group membership information in the user&#x2019;s logon token. Events in this subcategory are generated on the computer on which a logon session is created. For an interactive logon, the security audit event is generated on the computer that the user logged on to. For a network logon, such as accessing a shared folder on the network, the security audit event is generated on the computer hosting the resource.

  The recommended state for this setting is: Success.

  **Note:** A Windows 10, Server 2016 or higher OS is required to access and set this value in Group Policy.'
  impact 1.0
  tag 'windows': %w[2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '17.5.2'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('Only for Windows Server 2016, 2019') do
    ((os[:name].include? '2016') || (os[:name].include? '2019'))
  end
  describe audit_policy do
    its('Group Membership') { should eq 'Success' }
  end
end

control 'windows-160' do
  title 'Ensure \'Audit Logoff\' is set to \'Success\''
  desc 'This subcategory reports when a user logs off from the system. These events occur on the accessed computer. For interactive logons, the generation of these events occurs on the computer that is logged on to. If a network logon takes place to access a share, these events generate on the computer that hosts the accessed resource. If you configure this setting to No auditing, it is difficult or impossible to determine which user has accessed or attempted to access organization computers. Events for this subcategory include:

  * 4634: An account was logged off.
  * 4647: User initiated logoff.
  The recommended state for this setting is: Success.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '17.5.2'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '17.5.3'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe audit_policy do
    its('Logoff') { should eq 'Success' }
  end
end

control 'windows-161' do
  title 'Ensure \'Audit Logon\' is set to \'Success and Failure\''
  desc 'This subcategory reports when a user attempts to log on to the system. These events occur on the accessed computer. For interactive logons, the generation of these events occurs on the computer that is logged on to. If a network logon takes place to access a share, these events generate on the computer that hosts the accessed resource. If you configure this setting to No auditing, it is difficult or impossible to determine which user has accessed or attempted to access organization computers. Events for this subcategory include:

  * 4624: An account was successfully logged on.
  * 4625: An account failed to log on.
  * 4648: A logon was attempted using explicit credentials.
  * 4675: SIDs were filtered.
  The recommended state for this setting is: Success and Failure.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '17.5.3'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '17.5.4'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe audit_policy do
    its('Logon') { should eq 'Success and Failure' }
  end
end

control 'windows-162' do
  title 'Ensure \'Audit Other Logon/Logoff Events\' is set to \'Success and Failure\''
  desc 'This subcategory reports other logon/logoff-related events, such as Terminal Services session disconnects and reconnects, using RunAs to run processes under a different account, and locking and unlocking a workstation. Events for this subcategory include:

  * 4649: A replay attack was detected.
  * 4778: A session was reconnected to a Window Station.
  * 4779: A session was disconnected from a Window Station.
  * 4800: The workstation was locked.
  * 4801: The workstation was unlocked.
  * 4802: The screen saver was invoked.
  * 4803: The screen saver was dismissed.
  * 5378: The requested credentials delegation was disallowed by policy.
  * 5632: A request was made to authenticate to a wireless network.
  * 5633: A request was made to authenticate to a wired network.
  The recommended state for this setting is: Success and Failure.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '17.5.4'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '17.5.5'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe audit_policy do
    its('Other Logon/Logoff Events') { should eq 'Success and Failure' }
  end
end

control 'windows-163' do
  title 'Ensure \'Audit Special Logon\' is set to \'Success\''
  desc 'This subcategory reports when a special logon is used. A special logon is a logon that has administrator-equivalent privileges and can be used to elevate a process to a higher level. Events for this subcategory include:

  * 4964 : Special groups have been assigned to a new logon.
  The recommended state for this setting is: Success.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '17.5.5'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '17.5.6'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe audit_policy do
    its('Special Logon') { should eq 'Success' }
  end
end

control 'windows-164' do
  title 'Ensure \'Audit Other Object Access Events\' is set to \'Success and Failure\''
  desc 'This policy setting allows you to audit events generated by the management of task scheduler jobs or COM+ objects.

  For scheduler jobs, the following are audited:

  * Job created.
  * Job deleted.
  * Job enabled.
  * Job disabled.
  * Job updated.
  For COM+ objects, the following are audited:

  * Catalog object added.
  * Catalog object updated.
  * Catalog object deleted.
  The recommended state for this setting is: Success and Failure.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '17.6.1'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '17.6.1'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe audit_policy do
    its('Other Object Access Events') { should eq 'Success and Failure' }
  end
end

control 'windows-165' do
  title 'Ensure \'Audit Removable Storage\' is set to \'Success and Failure\''
  desc 'This policy setting allows you to audit user attempts to access file system objects on a removable storage device. A security audit event is generated only for all objects for all types of access requested. If you configure this policy setting, an audit event is generated each time an account accesses a file system object on a removable storage. Success audits record successful attempts and Failure audits record unsuccessful attempts. If you do not configure this policy setting, no audit event is generated when an account accesses a file system object on a removable storage.

  The recommended state for this setting is: Success and Failure.

  **Note:** A Windows 8, Server 2012 (non-R2) or higher OS is required to access and set this value in Group Policy.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '17.6.2'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '17.6.2'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe audit_policy do
    its('Removable Storage') { should eq 'Success and Failure' }
  end
end

control 'windows-166' do
  title 'Ensure \'Audit Audit Policy Change\' is set to \'Success and Failure\''
  desc 'This subcategory reports changes in audit policy including SACL changes. Events for this subcategory include:

  * 4715: The audit policy (SACL) on an object was changed.
  * 4719: System audit policy was changed.
  * 4902: The Per-user audit policy table was created.
  * 4904: An attempt was made to register a security event source.
  * 4905: An attempt was made to unregister a security event source.
  * 4906: The CrashOnAuditFail value has changed.
  * 4907: Auditing settings on object were changed.
  * 4908: Special Groups Logon table modified.
  * 4912: Per User Audit Policy was changed.
  The recommended state for this setting is: Success and Failure.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '17.7.1'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '17.7.1'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe audit_policy do
    its('Audit Policy Change') { should eq 'Success and Failure' }
  end
end

control 'windows-167' do
  title 'Ensure \'Audit Authentication Policy Change\' is set to \'Success\''
  desc 'This subcategory reports changes in authentication policy. Events for this subcategory include:

  * 4706: A new trust was created to a domain.
  * 4707: A trust to a domain was removed.
  * 4713: Kerberos policy was changed.
  * 4716: Trusted domain information was modified.
  * 4717: System security access was granted to an account.
  * 4718: System security access was removed from an account.
  * 4739: Domain Policy was changed.
  * 4864: A namespace collision was detected.
  * 4865: A trusted forest information entry was added.
  * 4866: A trusted forest information entry was removed.
  * 4867: A trusted forest information entry was modified.
  The recommended state for this setting is: Success.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '17.7.2'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '17.7.2'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe audit_policy do
    its('Authentication Policy Change') { should eq 'Success' }
  end
end

control 'windows-168' do
  title 'Ensure \'Audit Authorization Policy Change\' is set to \'Success\''
  desc 'This subcategory reports changes in authorization policy. Events for this subcategory include:

  * 4704: A user right was assigned.
  * 4705: A user right was removed.
  * 4706: A new trust was created to a domain.
  * 4707: A trust to a domain was removed.
  * 4714: Encrypted data recovery policy was changed.
  The recommended state for this setting is: Success.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '17.7.3'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '17.7.3'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe audit_policy do
    its('Authorization Policy Change') { should eq 'Success' }
  end
end

control 'windows-169' do
  title 'Ensure \'Audit Sensitive Privilege Use\' is set to \'Success and Failure\''
  desc 'This subcategory reports when a user account or service uses a sensitive privilege. A sensitive privilege includes the following user rights: Act as part of the operating system, Back up files and directories, Create a token object, Debug programs, Enable computer and user accounts to be trusted for delegation, Generate security audits, Impersonate a client after authentication, Load and unload device drivers, Manage auditing and security log, Modify firmware environment values, Replace a process-level token, Restore files and directories, and Take ownership of files or other objects. Auditing this subcategory will create a high volume of events. Events for this subcategory include:

  * 4672: Special privileges assigned to new logon.
  * 4673: A privileged service was called.
  * 4674: An operation was attempted on a privileged object.
  The recommended state for this setting is: Success and Failure.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '17.8.1'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '17.8.1'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe audit_policy do
    its('Sensitive Privilege Use') { should eq 'Success and Failure' }
  end
end

control 'windows-170' do
  title 'Ensure \'Audit IPsec Driver\' is set to \'Success and Failure\''
  desc 'This subcategory reports on the activities of the Internet Protocol security (IPsec) driver. Events for this subcategory include:

  * 4960: IPsec dropped an inbound packet that failed an integrity check. If this problem persists, it could indicate a network issue or that packets are being modified in transit to this computer. Verify that the packets sent from the remote computer are the same as those received by this computer. This error might also indicate interoperability problems with other IPsec implementations.
  * 4961: IPsec dropped an inbound packet that failed a replay check. If this problem persists, it could indicate a replay attack against this computer.
  * 4962: IPsec dropped an inbound packet that failed a replay check. The inbound packet had too low a sequence number to ensure it was not a replay.
  * 4963: IPsec dropped an inbound clear text packet that should have been secured. This is usually due to the remote computer changing its IPsec policy without informing this computer. This could also be a spoofing attack attempt.
  * 4965: IPsec received a packet from a remote computer with an incorrect Security Parameter Index (SPI). This is usually caused by malfunctioning hardware that is corrupting packets. If these errors persist, verify that the packets sent from the remote computer are the same as those received by this computer. This error may also indicate interoperability problems with other IPsec implementations. In that case, if connectivity is not impeded, then these events can be ignored.
  * 5478: IPsec Services has started successfully.
  * 5479: IPsec Services has been shut down successfully. The shutdown of IPsec Services can put the computer at greater risk of network attack or expose the computer to potential security risks.
  * 5480: IPsec Services failed to get the complete list of network interfaces on the computer. This poses a potential security risk because some of the network interfaces may not get the protection provided by the applied IPsec filters. Use the IP Security Monitor snap-in to diagnose the problem.
  * 5483: IPsec Services failed to initialize RPC server. IPsec Services could not be started.
  * 5484: IPsec Services has experienced a critical failure and has been shut down. The shutdown of IPsec Services can put the computer at greater risk of network attack or expose the computer to potential security risks.
  * 5485: IPsec Services failed to process some IPsec filters on a plug-and-play event for network interfaces. This poses a potential security risk because some of the network interfaces may not get the protection provided by the applied IPsec filters. Use the IP Security Monitor snap-in to diagnose the problem.
  The recommended state for this setting is: Success and Failure.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '17.9.1'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '17.9.1'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration'] # FIXME: check Baustein
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe audit_policy do
    its('IPsec Driver') { should eq 'Success and Failure' }
  end
end

control 'windows-171' do
  title 'Ensure \'Audit Other System Events\' is set to \'Success and Failure\''
  desc 'This subcategory reports on other system events. Events for this subcategory include:

  * 5024 : The Windows Firewall Service has started successfully.
  * 5025 : The Windows Firewall Service has been stopped.
  * 5027 : The Windows Firewall Service was unable to retrieve the security policy from the local storage. The service will continue enforcing the current policy.
  * 5028 : The Windows Firewall Service was unable to parse the new security policy. The service will continue with currently enforced policy.
  * 5029: The Windows Firewall Service failed to initialize the driver. The service will continue to enforce the current policy.
  * 5030: The Windows Firewall Service failed to start.
  * 5032: Windows Firewall was unable to notify the user that it blocked an application from accepting incoming connections on the network.
  * 5033 : The Windows Firewall Driver has started successfully.
  * 5034 : The Windows Firewall Driver has been stopped.
  * 5035 : The Windows Firewall Driver failed to start.
  * 5037 : The Windows Firewall Driver detected critical runtime error. Terminating.
  * 5058: Key file operation.
  * 5059: Key migration operation.
  The recommended state for this setting is: Success and Failure.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '17.9.2'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '17.9.2'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe audit_policy do
    its('Other System Events') { should eq 'Success and Failure' }
  end
end

control 'windows-172' do
  title 'Ensure \'Audit Security State Change\' is set to \'Success\''
  desc 'This subcategory reports changes in security state of the system, such as when the security subsystem starts and stops. Events for this subcategory include:

  * 4608: Windows is starting up.
  * 4609: Windows is shutting down.
  * 4616: The system time was changed.
  * 4621: Administrator recovered system from CrashOnAuditFail. Users who are not administrators will now be allowed to log on. Some auditable activity might not have been recorded.
  The recommended state for this setting is: Success.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '17.9.3'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '17.9.3'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe audit_policy do
    its('Security State Change') { should eq 'Success' }
  end
end

control 'windows-173' do
  title 'Ensure \'Audit Security System Extension\' is set to \'Success and Failure\''
  desc 'This subcategory reports the loading of extension code such as authentication packages by the security subsystem. Events for this subcategory include:

  * 4610: An authentication package has been loaded by the Local Security Authority.
  * 4611: A trusted logon process has been registered with the Local Security Authority.
  * 4614: A notification package has been loaded by the Security Account Manager.
  * 4622: A security package has been loaded by the Local Security Authority.
  * 4697: A service was installed in the system.
  The recommended state for this setting is: Success and Failure.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '17.9.4'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '17.9.4'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe audit_policy do
    its('Security System Extension') { should eq 'Success and Failure' }
  end
end

control 'windows-174' do
  title 'Ensure \'Audit System Integrity\' is set to \'Success and Failure\''
  desc 'This subcategory reports on violations of integrity of the security subsystem. Events for this subcategory include:

  * 4612 : Internal resources allocated for the queuing of audit messages have been exhausted, leading to the loss of some audits.
  * 4615 : Invalid use of LPC port.
  * 4618 : A monitored security event pattern has occurred.
  * 4816 : RPC detected an integrity violation while decrypting an incoming message.
  * 5038 : Code integrity determined that the image hash of a file is not valid. The file could be corrupt due to unauthorized modification or the invalid hash could indicate a potential disk device error.
  * 5056: A cryptographic self test was performed.
  * 5057: A cryptographic primitive operation failed.
  * 5060: Verification operation failed.
  * 5061: Cryptographic operation.
  * 5062: A kernel-mode cryptographic self test was performed.
  The recommended state for this setting is: Success and Failure.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '17.9.5'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '17.9.5'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe audit_policy do
    its('System Integrity') { should eq 'Success and Failure' }
  end
end

control 'windows-175' do
  title 'Ensure \'Prevent enabling lock screen camera\' is set to \'Enabled\''
  desc 'Disables the lock screen camera toggle switch in PC Settings and prevents a camera from being invoked on the lock screen.

  The recommended state for this setting is: Enabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.1.1.1'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.1.1.1'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Personalization') do
    it { should exist }
    it { should have_property 'NoLockScreenCamera' }
    its('NoLockScreenCamera') { should eq 1 }
  end
end

control 'windows-176' do
  title 'Ensure \'Prevent enabling lock screen slide show\' is set to \'Enabled\''
  desc 'Disables the lock screen slide show settings in PC Settings and prevents a slide show from playing on the lock screen.

  The recommended state for this setting is: Enabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.1.1.2'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.1.1.2'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Personalization') do
    it { should exist }
    it { should have_property 'NoLockScreenSlideshow' }
    its('NoLockScreenSlideshow') { should eq 1 }
  end
end

control 'windows-177' do
  title 'Ensure \'Allow Input Personalization\' is set to \'Disabled\''
  desc 'This policy enables the automatic learning component of input personalization that includes speech, inking, and typing. Automatic learning enables the collection of speech and handwriting patterns, typing history, contacts, and recent calendar information. It is required for the use of Cortana. Some of this collected information may be stored on the user\'s OneDrive, in the case of inking and typing; some of the information will be uploaded to Microsoft to personalize speech.

  The recommended state for this setting is: Disabled.'
  impact 1.0
  tag 'windows': %w[2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.1.2.1'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('Only for Windows Server 2016, 2019') do
    ((os[:name].include? '2016') || (os[:name].include? '2019'))
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\InputPersonalization') do
    it { should exist }
    it { should have_property 'AllowInputPersonalization' }
    its('AllowInputPersonalization') { should eq 0 }
  end
end

control 'windows-178' do
  title 'Ensure \'Allow Online Tips\' is set to \'Disabled\''
  desc 'This policy setting configures the retrieval of online tips and help for the Settings app.

  The recommended state for this setting is: Disabled. '
  impact 1.0
  tag 'windows': %w[2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.1.3'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('Only for Windows Server 2016, 2019') do
    ((os[:name].include? '2016') || (os[:name].include? '2019'))
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer') do
    it { should exist }
    it { should have_property 'AllowOnlineTips' }
    its('AllowOnlineTips') { should eq 0 }
  end
end

control 'windows-179' do
  title 'Ensure LAPS AdmPwd GPO Extension / CSE is installed (MS only)'
  desc 'In May 2015, Microsoft released the Local Administrator Password Solution (LAPS) tool, which is free and supported software that allows an organization to automatically set randomized and unique local Administrator account passwords on domain-attached workstations and member servers. The passwords are stored in a confidential attribute of the domain computer account and can be retrieved from Active Directory by approved Sysadmins when needed.

  The LAPS tool requires a small Active Directory Schema update in order to implement, as well as installation of a Group Policy Client Side Extension (CSE) on targeted computers. Please see the LAPS documentation for details.

  LAPS supports Windows Vista or newer workstation OSes, and Server 2003 or newer server OSes. LAPS does not support standalone computers - they must be joined to a domain.

  **Note:** Organizations that utilize 3rd-party commercial software to manage unique  complex local Administrator passwords on domain members may opt to disregard these LAPS recommendations.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.2.1'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.2.1'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('This Control only executes if attribute(\'ms_or_dc\') is set to MS') do
    attribute('ms_or_dc') == 'MS'
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\GPExtensions\\{D76B9641-3288-4f75-942D-087DE603E3EA}') do
    it { should exist }
    it { should have_property 'DllName' }
    its('DllName') { should eq 'C:\\Program Files\\LAPS\\CSE\\AdmPwd.dll' }
  end
end

control 'windows-180' do
  title 'Ensure \'Do not allow password expiration time longer than required by policy\' is set to \'Enabled\' (MS only)'
  desc 'In May 2015, Microsoft released the Local Administrator Password Solution (LAPS) tool, which is free and supported software that allows an organization to automatically set randomized and unique local Administrator account passwords on domain-attached workstations and member servers. The passwords are stored in a confidential attribute of the domain computer account and can be retrieved from Active Directory by approved Sysadmins when needed.

  The LAPS tool requires a small Active Directory Schema update in order to implement, as well as installation of a Group Policy Client Side Extension (CSE) on targeted computers. Please see the LAPS documentation for details.

  LAPS supports Windows Vista or newer workstation OSes, and Server 2003 or newer server OSes. LAPS does not support standalone computers - they must be joined to a domain.

  The recommended state for this setting is: Enabled.

  **Note:** Organizations that utilize 3rd-party commercial software to manage unique complex local Administrator passwords on domain members may opt to disregard these LAPS recommendations.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.2.2'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.2.2'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('This Control only executes if attribute(\'ms_or_dc\') is set to MS') do
    attribute('ms_or_dc') == 'MS'
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft Services\\AdmPwd') do
    it { should exist }
    it { should have_property 'PwdExpirationProtectionEnabled' }
    its('PwdExpirationProtectionEnabled') { should eq 1 }
  end
end

control 'windows-181' do
  title 'Ensure \'Enable Local Admin Password Management\' is set to \'Enabled\' (MS only)'
  desc 'In May 2015, Microsoft released the Local Administrator Password Solution (LAPS) tool, which is free and supported software that allows an organization to automatically set randomized and unique local Administrator account passwords on domain-attached workstations and member servers. The passwords are stored in a confidential attribute of the domain computer account and can be retrieved from Active Directory by approved Sysadmins when needed.

  The LAPS tool requires a small Active Directory Schema update in order to implement, as well as installation of a Group Policy Client Side Extension (CSE) on targeted computers. Please see the LAPS documentation for details.

  LAPS supports Windows Vista or newer workstation OSes, and Server 2003 or newer server OSes. LAPS does not support standalone computers - they must be joined to a domain.

  The recommended state for this setting is: Enabled.

  **Note:** Organizations that utilize 3rd-party commercial software to manage unique  complex local Administrator passwords on domain members may opt to disregard these LAPS recommendations.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.2.3'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.2.3'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('This Control only executes if attribute(\'ms_or_dc\') is set to MS') do
    attribute('ms_or_dc') == 'MS'
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft Services\\AdmPwd') do
    it { should exist }
    it { should have_property 'AdmPwdEnabled' }
    its('AdmPwdEnabled') { should eq 1 }
  end
end

control 'windows-182' do
  title 'Ensure \'Password Settings: Password Complexity\' is set to \'Enabled: Large letters + small letters + numbers + special characters\' (MS only)'
  desc 'In May 2015, Microsoft released the Local Administrator Password Solution (LAPS) tool, which is free and supported software that allows an organization to automatically set randomized and unique local Administrator account passwords on domain-attached workstations and member servers. The passwords are stored in a confidential attribute of the domain computer account and can be retrieved from Active Directory by approved Sysadmins when needed.

  The LAPS tool requires a small Active Directory Schema update in order to implement, as well as installation of a Group Policy Client Side Extension (CSE) on targeted computers. Please see the LAPS documentation for details.

  LAPS supports Windows Vista or newer workstation OSes, and Server 2003 or newer server OSes. LAPS does not support standalone computers - they must be joined to a domain.

  The recommended state for this setting is: Enabled: Large letters + small letters + numbers + special characters.

  **Note:** Organizations that utilize 3rd-party commercial software to manage unique  complex local Administrator passwords on domain members may opt to disregard these LAPS recommendations.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.2.4'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.2.4'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('This Control only executes if attribute(\'ms_or_dc\') is set to MS') do
    attribute('ms_or_dc') == 'MS'
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft Services\\AdmPwd') do
    it { should exist }
    it { should have_property 'PasswordComplexity' }
    its('PasswordComplexity') { should eq 4 }
  end
end

control 'windows-183' do
  title 'Ensure \'Password Settings: Password Length\' is set to \'Enabled: 15 or more\' (MS only)'
  desc 'In May 2015, Microsoft released the Local Administrator Password Solution (LAPS) tool, which is free and supported software that allows an organization to automatically set randomized and unique local Administrator account passwords on domain-attached workstations and member servers. The passwords are stored in a confidential attribute of the domain computer account and can be retrieved from Active Directory by approved Sysadmins when needed.

  The LAPS tool requires a small Active Directory Schema update in order to implement, as well as installation of a Group Policy Client Side Extension (CSE) on targeted computers. Please see the LAPS documentation for details.

  LAPS supports Windows Vista or newer workstation OSes, and Server 2003 or newer server OSes. LAPS does not support standalone computers - they must be joined to a domain.

  The recommended state for this setting is: Enabled: 15 or more.

  **Note:** Organizations that utilize 3rd-party commercial software to manage unique  complex local Administrator passwords on domain members may opt to disregard these LAPS recommendations.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.2.5'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.2.5'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('This Control only executes if attribute(\'ms_or_dc\') is set to MS') do
    attribute('ms_or_dc') == 'MS'
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft Services\\AdmPwd') do
    it { should exist }
    it { should have_property 'PasswordLength' }
    its('PasswordLength') { should be >= 15 }
  end
end

control 'windows-184' do
  title 'Ensure \'Password Settings: Password Age (Days)\' is set to \'Enabled: 30 or fewer\' (MS only)'
  desc 'In May 2015, Microsoft released the Local Administrator Password Solution (LAPS) tool, which is free and supported software that allows an organization to automatically set randomized and unique local Administrator account passwords on domain-attached workstations and member servers. The passwords are stored in a confidential attribute of the domain computer account and can be retrieved from Active Directory by approved Sysadmins when needed.

  The LAPS tool requires a small Active Directory Schema update in order to implement, as well as installation of a Group Policy Client Side Extension (CSE) on targeted computers. Please see the LAPS documentation for details.

  LAPS supports Windows Vista or newer workstation OSes, and Server 2003 or newer server OSes. LAPS does not support standalone computers - they must be joined to a domain.

  The recommended state for this setting is: Enabled: 30 or fewer.

  **Note:** Organizations that utilize 3rd-party commercial software to manage unique  complex local Administrator passwords on domain members may opt to disregard these LAPS recommendations.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.2.6'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.2.6'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('This Control only executes if attribute(\'ms_or_dc\') is set to MS') do
    attribute('ms_or_dc') == 'MS'
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft Services\\AdmPwd') do
    it { should exist }
    it { should have_property 'PasswordAgeDays' }
    its('PasswordAgeDays') { should be <= 30 }
  end
end

control 'windows-185' do
  title 'Ensure \'Apply UAC restrictions to local accounts on network logons\' is set to \'Enabled\' (MS only)'
  desc 'This setting controls whether local accounts can be used for remote administration via network logon (e.g., NET USE, connecting to C$, etc.). Local accounts are at high risk for credential theft when the same account and password is configured on multiple systems. Enabling this policy significantly reduces that risk.

  **Enabled:** Applies UAC token-filtering to local accounts on network logons. Membership in powerful group such as Administrators is disabled and powerful privileges are removed from the resulting access token. This configures the LocalAccountTokenFilterPolicy registry value to 0. This is the default behavior for Windows.

  **Disabled:** Allows local accounts to have full administrative rights when authenticating via network logon, by configuring the LocalAccountTokenFilterPolicy registry value to 1.

  For more information about local accounts and credential theft, review the [Mitigating Pass-the-Hash (PtH) Attacks and Other Credential Theft Techniques](http://www.microsoft.com/en-us/download/details.aspx?id=36036) documents.

  For more information about LocalAccountTokenFilterPolicy, see Microsoft Knowledge Base article 951016: [Description of User Account Control and remote restrictions in Windows Vista](https://support.microsoft.com/en-us/kb/951016).

  The recommended state for this setting is: Enabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.3.1'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.3.1'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('This Control only executes if attribute(\'ms_or_dc\') is set to MS') do
    attribute('ms_or_dc') == 'MS'
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System') do
    it { should exist }
    it { should have_property 'LocalAccountTokenFilterPolicy' }
    its('LocalAccountTokenFilterPolicy') { should eq 0 }
  end
end

control 'windows-186' do
  title 'Ensure \'Configure SMB v1 client driver\' is set to \'Enabled: Disable driver\''
  desc 'This setting configures the start type for the Server Message Block version 1 (SMBv1) client driver service (MRxSmb10), which is recommended to be disabled.

  The recommended state for this setting is: Enabled: Disable driver.

  **Note:** Do not, **under any circumstances**, configure this overall setting as Disabled, as doing so will delete the underlying registry entry altogether, which will cause serious problems.

  Rationale: Since September 2016, Microsoft has strongly encouraged that SMBv1 be disabled and no longer used on modern networks, as it is a 30 year old design that is much more vulnerable to attacks then much newer designs such as SMBv2 and SMBv3.

  More information on this can be found at the following links:

  [Stop using SMB1 | Storage at Microsoft](https://blogs.technet.microsoft.com/filecab/2016/09/16/stop-using-smb1/)

  [Disable SMB v1 in Managed Environments with Group Policy &#x2013; Stay Safe Cyber Security Blog](https://blogs.technet.microsoft.com/staysafe/2017/05/17/disable-smb-v1-in-managed-environments-with-ad-group-policy/)

  [Disabling SMBv1 through Group Policy &#x2013; Microsoft Security Guidance blog](https://blogs.technet.microsoft.com/secguide/2017/06/15/disabling-smbv1-through-group-policy/).

  The recommended state for this setting is: Enabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.3.2'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.3.2'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('This Control only executes if attribute(\'ms_or_dc\') is set to MS') do
    attribute('ms_or_dc') == 'MS'
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\mrxsmb10') do
    it { should exist }
    it { should have_property 'Start' }
    its('Start') { should eq 4 }
  end
end

control 'windows-187' do
  title 'Ensure \'Configure SMB v1 server\' is set to \'Disabled\''
  desc 'This setting configures the server-side processing of the Server Message Block version 1 (SMBv1) protocol.

  The recommended state for this setting is: Disabled.

  Rationale: Since September 2016, Microsoft has strongly encouraged that SMBv1 be disabled and no longer used on modern networks, as it is a 30 year old design that is much more vulnerable to attacks then much newer designs such as SMBv2 and SMBv3.

  More information on this can be found at the following links:

  [Stop using SMB1 | Storage at Microsoft](https://blogs.technet.microsoft.com/filecab/2016/09/16/stop-using-smb1/)

  [Disable SMB v1 in Managed Environments with Group Policy &#x2013; Stay Safe Cyber Security Blog](https://blogs.technet.microsoft.com/staysafe/2017/05/17/disable-smb-v1-in-managed-environments-with-ad-group-policy/)

  [Disabling SMBv1 through Group Policy &#x2013; Microsoft Security Guidance blog](https://blogs.technet.microsoft.com/secguide/2017/06/15/disabling-smbv1-through-group-policy/)'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.3.3'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.3.3'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters') do
    it { should exist }
    it { should have_property 'SMB1' }
    its('SMB1') { should eq 0 }
  end
end

control 'windows-188' do
  title 'Ensure \'Enable Structured Exception Handling Overwrite Protection (SEHOP)\' is set to \'Enabled\''
  desc 'Windows includes support for Structured Exception Handling Overwrite Protection (SEHOP). We recommend enabling this feature to improve the security profile of the computer.

  The recommended state for this setting is: Enabled.

  Rationale: This feature is designed to block exploits that use the Structured Exception Handler (SEH) overwrite technique. This protection mechanism is provided at run-time. Therefore, it helps protect applications regardless of whether they have been compiled with the latest improvements, such as the /SAFESEH option.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.3.4'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.3.4'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\kernel') do
    it { should exist }
    it { should have_property 'DisableExceptionChainValidation' }
    its('DisableExceptionChainValidation') { should eq 0 }
  end
end

control 'windows-189' do
  title 'Ensure \'WDigest Authentication\' is set to \'Disabled\''
  desc 'When WDigest authentication is enabled, Lsass.exe retains a copy of the user\'s plaintext password in memory, where it can be at risk of theft. If this setting is not configured, WDigest authentication is disabled in Windows 8.1 and in Windows Server 2012 R2; it is enabled by default in earlier versions of Windows and Windows Server.

  For more information about local accounts and credential theft, review the [Mitigating Pass-the-Hash (PtH) Attacks and Other Credential Theft Techniques](http://www.microsoft.com/en-us/download/details.aspx?id=36036) documents.

  For more information about UseLogonCredential, see Microsoft Knowledge Base article 2871997: [Microsoft Security Advisory Update to improve credentials protection and management May 13, 2014](https://support.microsoft.com/en-us/kb/2871997).

  The recommended state for this setting is: Disabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.3.5'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.3.6'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest') do
    it { should exist }
    it { should have_property 'UseLogonCredential' }
    its('UseLogonCredential') { should eq 0 }
  end
end

control 'windows-191' do
  title 'Ensure \'Turn on Windows Defender protection against Potentially Unwanted Applications\' is set to \'Enabled\''
  desc 'Enabling this Windows Defender feature will protect against Potentially Unwanted Applications (PUA), which are sneaky unwanted application bundlers or their bundled applications to deliver adware or malware.
  The recommended state for this setting is: Enabled.
  For more information, see this link: [Block Potentially Unwanted Applications with Windows Defender AV | Microsoft Docs](https://docs.microsoft.com/de-de/windows/security/threat-protection/windows-defender-antivirus/detect-block-potentially-unwanted-apps-windows-defender-antivirus)'
  impact 1.0
  tag 'windows': %w[2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.3.5'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('Only for Windows Server 2016, 2019') do
    ((os[:name].include? '2016') || (os[:name].include? '2019'))
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\MpEngine') do
    it { should exist }
    it { should have_property 'MpEnablePus' }
    its('MpEnablePus') { should eq 1 }
  end
end

control 'windows-192' do
  title 'Ensure \'MSS: (AutoAdminLogon) Enable Automatic Logon (not recommended)\' is set to \'Disabled\''
  desc 'This setting is separate from the Welcome screen feature in Windows XP and Windows Vista; if that feature is disabled, this setting is not disabled. If you configure a computer for automatic logon, anyone who can physically gain access to the computer can also gain access to everything that is on the computer, including any network or networks to which the computer is connected. Also, if you enable automatic logon, the password is stored in the registry in plaintext, and the specific registry key that stores this value is remotely readable by the Authenticated Users group.

  For additional information, see Microsoft Knowledge Base article 324737: [How to turn on automatic logon in Windows](https://support.microsoft.com/en-us/kb/324737).

  The recommended state for this setting is: Disabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.4.1'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.4.1'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon') do
    it { should exist }
    it { should have_property 'AutoAdminLogon' }
    its('AutoAdminLogon') { should eq 0 }
  end
end

control 'windows-193' do
  title 'Ensure \'MSS: (DisableIPSourceRouting IPv6) IP source routing protection level (protects against packet spoofing)\' is set to \'Enabled: Highest protection, source routing is completely disabled\''
  desc 'IP source routing is a mechanism that allows the sender to determine the IP route that a datagram should follow through the network.

  The recommended state for this setting is: Enabled: Highest protection, source routing is completely disabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.4.2'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.4.2'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M3', 'Sichere Administration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\Tcpip6\\Parameters') do
    it { should exist }
    it { should have_property 'DisableIPSourceRouting' }
    its('DisableIPSourceRouting') { should eq 2 }
  end
end

control 'windows-194' do
  title 'Ensure \'MSS: (DisableIPSourceRouting) IP source routing protection level (protects against packet spoofing)\' is set to \'Enabled: Highest protection, source routing is completely disabled\''
  desc 'IP source routing is a mechanism that allows the sender to determine the IP route that a datagram should take through the network. It is recommended to configure this setting to Not Defined for enterprise environments and to Highest Protection for high security environments to completely disable source routing.

  The recommended state for this setting is: Enabled: Highest protection, source routing is completely disabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.4.3'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.4.3'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\Tcpip\\Parameters') do
    it { should exist }
    it { should have_property 'DisableIPSourceRouting' }
    its('DisableIPSourceRouting') { should eq 2 }
  end
end

control 'windows-195' do
  title 'Ensure \'MSS: (EnableICMPRedirect) Allow ICMP redirects to override OSPF generated routes\' is set to \'Disabled\''
  desc 'Internet Control Message Protocol (ICMP) redirects cause the IPv4 stack to plumb host routes. These routes override the Open Shortest Path First (OSPF) generated routes.

  The recommended state for this setting is: Disabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.4.4'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.4.4'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\Tcpip\\Parameters') do
    it { should exist }
    it { should have_property 'EnableICMPRedirect' }
    its('EnableICMPRedirect') { should eq 0 }
  end
end

control 'windows-196' do
  title 'Ensure \'MSS: (KeepAliveTime) How often keep-alive packets are sent in milliseconds\' is set to \'Enabled: 300,000 or 5 minutes (recommended)\''
  desc 'This value controls how often TCP attempts to verify that an idle connection is still intact by sending a keep-alive packet. If the remote computer is still reachable, it acknowledges the keep-alive packet.

  The recommended state for this setting is: Enabled: 300,000 or 5 minutes (recommended).'
  impact 0.5
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.4.5'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.4.5'
  tag 'level': '2'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('This Control only executes if attribute(\'level_1_or_2\') is set to 2') do
    attribute('level_1_or_2') == 2
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\Tcpip\\Parameters') do
    it { should exist }
    it { should have_property 'KeepAliveTime' }
    its('KeepAliveTime') { should eq 300000 }
  end
end

control 'windows-197' do
  title 'Ensure \'MSS: (NoNameReleaseOnDemand) Allow the computer to ignore NetBIOS name release requests except from WINS servers\' is set to \'Enabled\''
  desc 'NetBIOS over TCP/IP is a network protocol that among other things provides a way to easily resolve NetBIOS names that are registered on Windows-based systems to the IP addresses that are configured on those systems. This setting determines whether the computer releases its NetBIOS name when it receives a name-release request.

  The recommended state for this setting is: Enabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.4.6'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.4.6'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\NetBT\\Parameters') do
    it { should exist }
    it { should have_property 'nonamereleaseondemand' }
    its('nonamereleaseondemand') { should eq 1 }
  end
end

control 'windows-198' do
  title 'Ensure \'MSS: (PerformRouterDiscovery) Allow IRDP to detect and configure Default Gateway addresses (could lead to DoS)\' is set to \'Disabled\''
  desc 'This setting is used to enable or disable the Internet Router Discovery Protocol (IRDP), which allows the system to detect and configure default gateway addresses automatically as described in RFC 1256 on a per-interface basis.

  The recommended state for this setting is: Disabled.'
  impact 0.5
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.4.7'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.4.7'
  tag 'level': '2'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('This Control only executes if attribute(\'level_1_or_2\') is set to 2') do
    attribute('level_1_or_2') == 2
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\Tcpip\\Parameters') do
    it { should exist }
    it { should have_property 'PerformRouterDiscovery' }
    its('PerformRouterDiscovery') { should eq 0 }
  end
end

control 'windows-199' do
  title 'Ensure \'MSS: (SafeDllSearchMode) Enable Safe DLL search mode (recommended)\' is set to \'Enabled\''
  desc 'The DLL search order can be configured to search for DLLs that are requested by running processes in one of two ways:

  * Search folders specified in the system path first, and then search the current working folder.
  * Search current working folder first, and then search the folders specified in the system path.
  When enabled, the registry value is set to 1. With a setting of 1, the system first searches the folders that are specified in the system path and then searches the current working folder. When disabled the registry value is set to 0 and the system first searches the current working folder and then searches the folders that are specified in the system path.

  Applications will be forced to search for DLLs in the system path first. For applications that require unique versions of these DLLs that are included with the application, this entry could cause performance or stability problems.

  The recommended state for this setting is: Enabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.4.8'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.4.8'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager') do
    it { should exist }
    it { should have_property 'SafeDllSearchMode' }
    its('SafeDllSearchMode') { should eq 1 }
  end
end

control 'windows-200' do
  title 'Ensure \'MSS: (ScreenSaverGracePeriod) The time in seconds before the screen saver grace period expires (0 recommended)\' is set to \'Enabled: 5 or fewer seconds\''
  desc ' Windows includes a grace period between when the screen saver is launched and when the console is actually locked automatically when screen saver locking is enabled.

  The recommended state for this setting is: Enabled: 5 or fewer seconds.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.4.9'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.4.9'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon') do
    it { should exist }
    it { should have_property 'ScreenSaverGracePeriod' }
    its('ScreenSaverGracePeriod') { should be <= 5 }
  end
end

control 'windows-201' do
  title 'Ensure \'MSS: (TcpMaxDataRetransmissions IPv6) How many times unacknowledged data is retransmitted\' is set to \'Enabled: 3\''
  desc 'This setting controls the number of times that TCP retransmits an individual data segment (non-connect segment) before the connection is aborted. The retransmission time-out is doubled with each successive retransmission on a connection. It is reset when responses resume. The base time-out value is dynamically determined by the measured round-trip time on the connection.

  The recommended state for this setting is: Enabled: 3.'
  impact 0.5
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.4.10'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.4.10'
  tag 'level': '2'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('This Control only executes if attribute(\'level_1_or_2\') is set to 2') do
    attribute('level_1_or_2') == 2
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\TCPIP6\\Parameters') do
    it { should exist }
    it { should have_property 'tcpmaxdataretransmissions' }
    its('tcpmaxdataretransmissions') { should eq 3 }
  end
end

control 'windows-202' do
  title 'Ensure \'MSS: (TcpMaxDataRetransmissions) How many times unacknowledged data is retransmitted\' is set to \'Enabled: 3\''
  desc 'This setting controls the number of times that TCP retransmits an individual data segment (non-connect segment) before the connection is aborted. The retransmission time-out is doubled with each successive retransmission on a connection. It is reset when responses resume. The base time-out value is dynamically determined by the measured round-trip time on the connection.

  The recommended state for this setting is: Enabled: 3.'
  impact 0.5
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.4.11'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.4.11'
  tag 'level': '2'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('This Control only executes if attribute(\'level_1_or_2\') is set to 2') do
    attribute('level_1_or_2') == 2
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\Tcpip\\Parameters') do
    it { should exist }
    it { should have_property 'tcpmaxdataretransmissions' }
    its('tcpmaxdataretransmissions') { should eq 3 }
  end
end

control 'windows-203' do
  title 'Ensure \'MSS: (WarningLevel) Percentage threshold for the security event log at which the system will generate a warning\' is set to \'Enabled: 90% or less\''
  desc 'This setting can generate a security audit in the Security event log when the log reaches a user-defined threshold.

  The recommended state for this setting is: Enabled: 90% or less.

  **Note:** If log settings are configured to Overwrite events as needed or Overwrite events older than x days, this event will not be generated.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.4.12'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.4.12'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Eventlog\\Security') do
    it { should exist }
    it { should have_property 'WarningLevel' }
    its('WarningLevel') { should be <= 90 }
  end
end

control 'windows-204' do
  title 'Set \'NetBIOS node type\' to \'P-node\' (Ensure NetBT Parameter \'NodeType\' is set to \'0x2 (2)\') (MS Only)'
  desc 'This parameter determines which method NetBIOS over TCP/IP (NetBT) will use to register and resolve names.

  * A B-node (broadcast) system only uses broadcasts.
  * A P-node (point-to-point) system uses only name queries to a name server (WINS).
  * An M-node (mixed) system broadcasts first, then queries the name server (WINS).
  * An H-node (hybrid) system queries the name server (WINS) first, then broadcasts.
  The recommended state for this setting is: NodeType - 0x2 (2).'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.5.4.1'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.5.4.1'
  tag 'level': '2'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('This Control only executes if attribute(\'level_1_or_2\') is set to 2 and attribute(\'ms_or_dc\') is set to MS') do
    ((attribute('level_1_or_2') == 2) && (attribute('ms_or_dc') == 'MS'))
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\Netbt\\Parameters') do
    it { should have_property 'NodeType' }
    its('NodeType') { should eq 2 }
  end
end

control 'windows-205' do
  title 'Ensure \'Turn off multicast name resolution\' is set to \'Enabled\' (MS Only)'
  desc 'LLMNR is a secondary name resolution protocol. With LLMNR, queries are sent using multicast over a local network link on a single subnet from a client computer to another client computer on the same subnet that also has LLMNR enabled. LLMNR does not require a DNS server or DNS client configuration, and provides name resolution in scenarios in which conventional DNS name resolution is not possible.

  The recommended state for this setting is: Enabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.5.4.2'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.5.4.2'
  tag 'level': '2'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('This Control only executes if attribute(\'level_1_or_2\') is set to 2 and attribute(\'ms_or_dc\') is set to MS') do
    ((attribute('level_1_or_2') == 2) && (attribute('ms_or_dc') == 'MS'))
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient') do
    it { should have_property 'EnableMulticast' }
    its('EnableMulticast') { should eq 0 }
  end
end

control 'windows-206' do
  title ' Ensure \'Enable Font Providers\' is set to \'Disabled\''
  desc 'This policy setting determines whether Windows is allowed to download fonts and font catalog data from an online font provider.

  The recommended state for this setting is: Disabled.'
  impact 0.5
  tag 'windows': %w[2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.5.5.1'
  tag 'level': '2'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('Only for Windows Server 2016, 2019 and if attribute(\'level_1_or_2\') is set to 2') do
    (((os[:name].include? '2016') || (os[:name].include? '2019')) && attribute('level_1_or_2') == 2)
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\System') do
    it { should exist }
    it { should have_property 'EnableFontProviders' }
    its('EnableFontProviders') { should eq 0 }
  end
end

control 'windows-207' do
  title 'Ensure \'Enable insecure guest logons\' is set to \'Disabled\''
  desc 'This policy setting determines if the SMB client will allow insecure guest logons to an SMB server.

  The recommended state for this setting is: Disabled.'
  impact 1.0
  tag 'windows': %w[2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.5.8.1'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('Only for Windows Server 2016, 2019') do
    ((os[:name].include? '2016') || (os[:name].include? '2019'))
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\LanmanWorkstation') do
    it { should exist }
    it { should have_property 'AllowInsecureGuestAuth' }
    its('AllowInsecureGuestAuth') { should eq 0 }
  end
end

control 'windows-208' do
  title 'Ensure \'Turn on Mapper I/O (LLTDIO) driver\' is set to \'Disabled\''
  desc 'This policy setting changes the operational behavior of the Mapper I/O network protocol driver.

  LLTDIO allows a computer to discover the topology of a network it\'s connected to. It also allows a computer to initiate Quality-of-Service requests such as bandwidth estimation and network health analysis.

  The recommended state for this setting is: Disabled.'
  impact 0.5
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.5.9.1'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.5.9.1'
  tag 'level': '2'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('This Control only executes if attribute(\'level_1_or_2\') is set to 2') do
    attribute('level_1_or_2') == 2
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\LLTD') do
    it { should exist }
    it { should have_property 'AllowLLTDIOOndomain' }
    its('AllowLLTDIOOndomain') { should eq 0 }
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\LLTD') do
    it { should exist }
    it { should have_property 'AllowLLTDIOOnPublicNet' }
    its('AllowLLTDIOOnPublicNet') { should eq 0 }
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\LLTD') do
    it { should exist }
    it { should have_property 'EnableLLTDIO' }
    its('EnableLLTDIO') { should eq 0 }
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\LLTD') do
    it { should exist }
    it { should have_property 'ProhibitLLTDIOOnPrivateNet' }
    its('ProhibitLLTDIOOnPrivateNet') { should eq 0 }
  end
end

control 'windows-209' do
  title 'Ensure \'Turn on Responder (RSPNDR) driver\' is set to \'Disabled\''
  desc 'This policy setting changes the operational behavior of the Responder network protocol driver.

  The Responder allows a computer to participate in Link Layer Topology Discovery requests so that it can be discovered and located on the network. It also allows a computer to participate in Quality-of-Service activities such as bandwidth estimation and network health analysis.

  The recommended state for this setting is: Disabled.'
  impact 0.5
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.5.9.2'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.5.9.2'
  tag 'level': '2'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('This Control only executes if attribute(\'level_1_or_2\') is set to 2') do
    attribute('level_1_or_2') == 2
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\LLTD') do
    it { should exist }
    it { should have_property 'AllowRspndrOndomain' }
    its('AllowRspndrOndomain') { should eq 0 }
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\LLTD') do
    it { should exist }
    it { should have_property 'AllowRspndrOnPublicNet' }
    its('AllowRspndrOnPublicNet') { should eq 0 }
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\LLTD') do
    it { should exist }
    it { should have_property 'EnableRspndr' }
    its('EnableRspndr') { should eq 0 }
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\LLTD') do
    it { should exist }
    it { should have_property 'ProhibitRspndrOnPrivateNet' }
    its('ProhibitRspndrOnPrivateNet') { should eq 0 }
  end
end

control 'windows-210' do
  title 'Ensure \'Turn off Microsoft Peer-to-Peer Networking Services\' is set to \'Enabled\''
  desc 'The Peer Name Resolution Protocol (PNRP) allows for distributed resolution of a name to an IPv6 address and port number. The protocol operates in the context of **clouds**. A cloud is a set of peer computers that can communicate with each other by using the same IPv6 scope.

  Peer-to-Peer protocols allow for applications in the areas of RTC, collaboration, content distribution and distributed processing.

  The recommended state for this setting is: Enabled.'
  impact 0.5
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.5.10.2'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.5.10.2'
  tag 'level': '2'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('This Control only executes if attribute(\'level_1_or_2\') is set to 2') do
    attribute('level_1_or_2') == 2
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Peernet') do
    it { should exist }
    it { should have_property 'Disabled' }
    its('Disabled') { should eq 1 }
  end
end

control 'windows-211' do
  title 'Ensure \'Prohibit installation and configuration of Network Bridge on your DNS domain network\' is set to \'Enabled\''
  desc 'You can use this procedure to controls user\'s ability to install and configure a Network Bridge.

  The recommended state for this setting is: Enabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.5.11.2'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.5.11.2'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Network Connections') do
    it { should exist }
    it { should have_property 'NC_AllowNetBridge_NLA' }
    its('NC_AllowNetBridge_NLA') { should eq 0 }
  end
end

control 'windows-212' do
  title 'Ensure \'Prohibit use of Internet Connection Sharing on your DNS domain network\' is set to \'Enabled\''
  desc 'Although this "legacy" setting traditionally applied to the use of Internet Connection Sharing (ICS) in Windows 2000, Windows XP & Server 2003, this setting now freshly applies to the Mobile Hotspot feature in Windows 10 & Server 2016.

  The recommended state for this setting is: Enabled.'
  impact 1.0
  tag 'windows': %w[2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.5.11.3'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('Only for Windows Server 2016, 2019') do
    ((os[:name].include? '2016') || (os[:name].include? '2019'))
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Network Connections') do
    it { should exist }
    it { should have_property 'NC_ShowSharedAccessUI' }
    its('NC_ShowSharedAccessUI') { should eq 0 }
  end
end

control 'windows-213' do
  title 'Ensure \'Require domain users to elevate when setting a network\'s location\' is set to \'Enabled\''
  desc 'This policy setting determines whether to require domain users to elevate when setting a network\'s location.

  The recommended state for this setting is: Enabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.5.11.3'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.5.11.4'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Network Connections') do
    it { should exist }
    it { should have_property 'NC_StdDomainUserSetLocation' }
    its('NC_StdDomainUserSetLocation') { should eq 1 }
  end
end

control 'windows-214' do
  title 'Ensure \'Hardened UNC Paths\' is set to \'Enabled, with Require Mutual Authentication and Require Integrity set for all NETLOGON and SYSVOL shares\''
  desc 'This policy setting configures secure access to UNC paths.

  The recommended state for this setting is: Enabled, with \'Require Mutual Authentication\' and \'Require Integrity\' set for all NETLOGON and SYSVOL shares.

  **Note:** If the environment exclusively contains Windows 8.0 / Server 2012 or higher systems, then the \'Privacy\' setting may (optionally) also be set to enable SMB encryption. However, using SMB encryption will render the targeted share paths completely inaccessible by older OSes, so only use this additional option with caution and thorough testing.

  Rationale: In February 2015, Microsoft released a new control mechanism to mitigate a security risk in Group Policy as part of the [MS15-011](https://technet.microsoft.com/library/security/MS15-011) / [MSKB 3000483](https://support.microsoft.com/en-us/kb/3000483) security update. This mechanism requires both the installation of the new security update and also the deployment of specific group policy settings to all computers on the domain from Windows Vista / Server 2008 (non-R2) or higher (the associated security patch to enable this feature was not released for Server 2003). A new group policy template (NetworkProvider.admx/adml) was also provided with the security update.

  Once the new GPO template is in place, the following are the minimum requirements to remediate the Group Policy security risk:

  \\\\*\\NETLOGON RequireMutualAuthentication=1, RequireIntegrity=1\\\\*\\SYSVOL RequireMutualAuthentication=1, RequireIntegrity=1

  **Note:** A reboot may be required after the setting is applied to a client machine to access the above paths.

  Additional guidance on the deployment of this security setting is available from the Microsoft Premier Field Engineering (PFE) Platforms TechNet Blog here: [Guidance on Deployment of MS15-011 and MS15-014](http://blogs.technet.com/b/askpfeplat/archive/2015/02/23/guidance-on-deployment-of-ms15-011-and-ms15-014.aspx).'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.5.14.1'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.4.14.1'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\NetworkProvider\\HardenedPaths') do
    it { should exist }
    it { should have_property '\\\*\\NETLOGON' }
    it { should have_property '\\\*\\SYSVOL' }
    its('\\\*\\NETLOGON') { should match(//) }
    its('\\\*\\SYSVOL') { should match(//) }
  end
end

control 'windows-215' do
  title 'Disable IPv6 (Ensure TCPIP6 Parameter \'DisabledComponents\' is set to \'0xff (255)\')'
  desc 'Internet Protocol version 6 (IPv6) is a set of protocols that computers use to exchange information over the Internet and over home and business networks. IPv6 allows for many more IP addresses to be assigned than IPv4 did. Older networking, hosts and operating systems may not support IPv6 natively.

  The recommended state for this setting is: DisabledComponents - 0xff (255)'
  impact 0.5
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.5.19.2.1'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.4.19.2.1'
  tag 'level': '2'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('This Control only executes if attribute(\'level_1_or_2\') is set to 2') do
    attribute('level_1_or_2') == 2
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\TCPIP6\\Parameters') do
    it { should exist }
    it { should have_property 'DisabledComponents' }
    its('DisabledComponents') { should eq 255 }
  end
end

control 'windows-216' do
  title 'Ensure \'Configuration of wireless settings using Windows Connect Now\' is set to \'Disabled\''
  desc 'This policy setting allows the configuration of wireless settings using Windows Connect Now (WCN). The WCN Registrar enables the discovery and configuration of devices over Ethernet (UPnP) over in-band 802.11 Wi-Fi through the Windows Portable Device API (WPD) and via USB Flash drives. Additional options are available to allow discovery and configuration over a specific medium.

  The recommended state for this setting is: Disabled.'
  impact 0.5
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.5.20.1'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.5.20.1'
  tag 'level': '2'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('This Control only executes if attribute(\'level_1_or_2\') is set to 2') do
    attribute('level_1_or_2') == 2
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WCN\\Registrars') do
    it { should exist }
    it { should have_property 'EnableRegistrars' }
    its('EnableRegistrars') { should eq 0 }
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WCN\\Registrars') do
    it { should exist }
    it { should have_property 'DisableUPnPRegistrar' }
    its('DisableUPnPRegistrar') { should eq 0 }
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WCN\\Registrars') do
    it { should exist }
    it { should have_property 'DisableInBand802DOT11Registrar' }
    its('DisableInBand802DOT11Registrar') { should eq 0 }
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WCN\\Registrars') do
    it { should exist }
    it { should have_property 'DisableFlashConfigRegistrar' }
    its('DisableFlashConfigRegistrar') { should eq 0 }
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WCN\\Registrars') do
    it { should exist }
    it { should have_property 'DisableWPDRegistrar' }
    its('DisableWPDRegistrar') { should eq 0 }
  end
end

control 'windows-217' do
  title 'Ensure \'Prohibit access of the Windows Connect Now wizards\' is set to \'Enabled\''
  desc 'This policy setting prohibits access to Windows Connect Now (WCN) wizards.

  The recommended state for this setting is: Enabled.'
  impact 0.5
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.5.20.2'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.5.20.2'
  tag 'level': '2'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('This Control only executes if attribute(\'level_1_or_2\') is set to 2') do
    attribute('level_1_or_2') == 2
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WCN\\UI') do
    it { should exist }
    it { should have_property 'DisableWcnUi' }
    its('DisableWcnUi') { should eq 1 }
  end
end

control 'windows-218' do
  title 'Ensure \'Minimize the number of simultaneous connections to the Internet or a Windows Domain\' is set to \'Enabled\''
  desc 'This policy setting prevents computers from connecting to both a domain based network and a non-domain based network at the same time.

  The recommended state for this setting is: Enabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.5.21.1'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.5.21.1'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WcmSvc\\GroupPolicy') do
    it { should exist }
    it { should have_property 'fMinimizeConnections' }
    its('fMinimizeConnections') { should eq 1 }
  end
end

control 'windows-219' do
  title 'Ensure \'Prohibit connection to non-domain networks when connected to domain authenticated network\' is set to \'Enabled\' (MS only)'
  desc 'This policy setting prevents computers from connecting to both a domain based network and a non-domain based network at the same time.

  The recommended state for this setting is: Enabled.'
  impact 0.5
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.5.21.2'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.5.21.2'
  tag 'level': '2'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('This Control only executes if attribute(\'level_1_or_2\') is set to 2 and attribute(\'ms_or_dc\') is set to MS') do
    ((attribute('level_1_or_2') == 2) && (attribute('ms_or_dc') == 'MS'))
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WcmSvc\\GroupPolicy') do
    it { should have_property 'fBlockNonDomain' }
    its('fBlockNonDomain') { should eq 1 }
  end
end

control 'windows-220' do
  title 'Ensure \'Include command line in process creation events\' is set to \'Disabled\''
  desc 'This policy setting determines what information is logged in security audit events when a new process has been created.

  The recommended state for this setting is: Disabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.8.3.1'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.8.3.1'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Audit') do
    it { should exist }
    it { should have_property 'ProcessCreationIncludeCmdLine_Enabled' }
    its('ProcessCreationIncludeCmdLine_Enabled') { should eq 0 }
  end
end

control 'windows-221' do
  title 'Ensure \'Remote host allows delegation of non-exportable credentials\' is set to \'Enabled\''
  desc 'Remote host allows delegation of non-exportable credentials. When using credential delegation, devices provide an exportable version of credentials to the remote host. This exposes users to the risk of credential theft from attackers on the remote host. The Restricted Admin Mode and Windows Defender Remote Credential Guard features are two options to help protect against this risk.

  The recommended state for this setting is: Enabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.8.4.1'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.8.4.1'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\CredentialsDelegation') do
    it { should have_property 'AllowProtectedCreds' }
    its('AllowProtectedCreds') { should eq 1 }
  end
end

control 'windows-222' do
  title 'Ensure \'Boot-Start Driver Initialization Policy\' is set to \'Enabled: Good, unknown and bad but critical\''
  desc 'This policy setting allows you to specify which boot-start drivers are initialized based on a classification determined by an Early Launch Antimalware boot-start driver. The Early Launch Antimalware boot-start driver can return the following classifications for each boot-start driver:

  * Good: The driver has been signed and has not been tampered with.
  * Bad: The driver has been identified as malware. It is recommended that you do not allow known bad drivers to be initialized.
  * Bad, but required for boot: The driver has been identified as malware, but the computer cannot successfully boot without loading this driver.
  * Unknown: This driver has not been attested to by your malware detection application and has not been classified by the Early Launch Antimalware boot-start driver.
  If you enable this policy setting you will be able to choose which boot-start drivers to initialize the next time the computer is started.

  If your malware detection application does not include an Early Launch Antimalware boot-start driver or if your Early Launch Antimalware boot-start driver has been disabled, this setting has no effect and all boot-start drivers are initialized.

  The recommended state for this setting is: Enabled: Good, unknown and bad but critical.

  Rationale: This policy setting helps reduce the impact of malware that has already infected your system'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.8.14.1'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.8.14.1'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Policies\\EarlyLaunch') do
    it { should exist }
    it { should have_property 'DriverLoadPolicy' }
    its('DriverLoadPolicy') { should eq 3 }
  end
end

control 'windows-223' do
  title 'Ensure \'Configure registry policy processing: Do not apply during periodic background processing\' is set to \'Enabled: FALSE\''
  desc 'The \'Do not apply during periodic background processing\' option prevents the system from updating affected policies in the background while the computer is in use. When background updates are disabled, policy changes will not take effect until the next user logon or system restart.

  The recommended state for this setting is: Enabled: FALSE (unchecked).'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.8.21.2'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.8.21.2'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Group Policy\\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}') do
    it { should exist }
    it { should have_property 'NoBackgroundPolicy' }
    its('NoBackgroundPolicy') { should eq 0 }
  end
end

control 'windows-224' do
  title 'Ensure \'Configure registry policy processing: Process even if the Group Policy objects have not changed\' is set to \'Enabled: TRUE\''
  desc 'The \'Process even if the Group Policy objects have not changed\' option updates and reapplies policies even if the policies have not changed.

  The recommended state for this setting is: Enabled: TRUE (checked).'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.8.21.3'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.8.21.3'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Group Policy\\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}') do
    it { should exist }
    it { should have_property 'NoGPOListChanges' }
    its('NoGPOListChanges') { should eq 0 }
  end
end

control 'windows-225' do
  title 'Ensure \'Continue experiences on this device\' is set to \'Disabled\''
  desc 'This policy setting determines whether the Windows device is allowed to participate in cross-device experiences (continue experiences).

  The recommended state for this setting is: Disabled.'
  impact 1.0
  tag 'windows': %w[2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.8.21.4'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('Only for Windows Server 2016, 2019') do
    ((os[:name].include? '2016') || (os[:name].include? '2019'))
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\System') do
    it { should exist }
    it { should have_property 'EnableCdp' }
    its('EnableCdp') { should eq 0 }
  end
end

control 'windows-226' do
  title 'Ensure \'Turn off background refresh of Group Policy\' is set to \'Disabled\''
  desc 'This policy setting prevents Group Policy from being updated while the computer is in use. This policy setting applies to Group Policy for computers, users and Domain Controllers.

  The recommended state for this setting is: Disabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.8.21.4'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.8.21.5'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']

  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System') do
    it { should exist }
    it { should_not have_property 'DisableBkGndGroupPolicy' }
  end
end

control 'windows-227' do
  title 'Ensure \'Turn off downloading of print drivers over HTTP\' is set to \'Enabled\''
  desc 'This policy setting controls whether the computer can download print driver packages over HTTP. To set up HTTP printing, printer drivers that are not available in the standard operating system installation might need to be downloaded over HTTP.

  The recommended state for this setting is: Enabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.8.22.1.1'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.8.22.1.1'
  tag 'level': '2'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('This Control only executes if attribute(\'level_1_or_2\') is set to 2') do
    attribute('level_1_or_2') == 2
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows NT\\Printers') do
    it { should exist }
    it { should have_property 'DisableWebPnPDownload' }
    its('DisableWebPnPDownload') { should eq 1 }
  end
end

control 'windows-228' do
  title 'Ensure \'Turn off handwriting personalization data sharing\' is set to \'Enabled\''
  desc 'This setting turns off data sharing from the handwriting recognition personalization tool.

  The handwriting recognition personalization tool enables Tablet PC users to adapt handwriting recognition to their own writing style by providing writing samples. The tool can optionally share user writing samples with Microsoft to improve handwriting recognition in future versions of Windows. The tool generates reports and transmits them to Microsoft over a secure connection.

  The recommended state for this setting is: Enabled.'
  impact 0.5
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.8.22.1.2'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.8.22.1.2'
  tag 'level': '2'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('This Control only executes if attribute(\'level_1_or_2\') is set to 2') do
    attribute('level_1_or_2') == 2
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\TabletPC') do
    it { should exist }
    it { should have_property 'PreventHandwritingDataSharing' }
    its('PreventHandwritingDataSharing') { should eq 1 }
  end
end

control 'windows-229' do
  title 'Ensure \'Turn off handwriting recognition error reporting\' is set to \'Enabled\''
  desc 'Turns off the handwriting recognition error reporting tool.

  The handwriting recognition error reporting tool enables users to report errors encountered in Tablet PC Input Panel. The tool generates error reports and transmits them to Microsoft over a secure connection. Microsoft uses these error reports to improve handwriting recognition in future versions of Windows.

  The recommended state for this setting is: Enabled.'
  impact 0.5
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.8.22.1.3'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.8.22.1.3'
  tag 'level': '2'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('This Control only executes if attribute(\'level_1_or_2\') is set to 2') do
    attribute('level_1_or_2') == 2
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\HandwritingErrorReports') do
    it { should exist }
    it { should have_property 'PreventHandwritingErrorReports' }
    its('PreventHandwritingErrorReports') { should eq 1 }
  end
end

control 'windows-230' do
  title 'Ensure \'Turn off Internet Connection Wizard if URL connection is referring to Microsoft.com\' is set to \'Enabled\''
  desc 'This policy setting specifies whether the Internet Connection Wizard can connect to Microsoft to download a list of Internet Service Providers (ISPs).

  The recommended state for this setting is: Enabled.'
  impact 0.5
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.8.22.1.4'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.8.22.1.4'
  tag 'level': '2'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('This Control only executes if attribute(\'level_1_or_2\') is set to 2') do
    attribute('level_1_or_2') == 2
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Internet Connection Wizard') do
    it { should exist }
    it { should have_property 'ExitOnMSICW' }
    its('ExitOnMSICW') { should eq 1 }
  end
end

control 'windows-231' do
  title 'Ensure \'Turn off Internet download for Web publishing and online ordering wizards\' is set to \'Enabled\''
  desc 'This policy setting controls whether Windows will download a list of providers for the Web publishing and online ordering wizards.

  The recommended state for this setting is: Enabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.8.22.1.5'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.8.22.1.5'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer') do
    it { should exist }
    it { should have_property 'NoWebServices' }
    its('NoWebServices') { should eq 1 }
  end
end

control 'windows-232' do
  title 'Ensure \'Turn off printing over HTTP\' is set to \'Enabled\''
  desc 'This policy setting allows you to disable the client computer\'s ability to print over HTTP, which allows the computer to print to printers on the intranet as well as the Internet.

  The recommended state for this setting is: Enabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.8.22.1.6'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.8.22.1.6'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows NT\\Printers') do
    it { should exist }
    it { should have_property 'DisableHTTPPrinting' }
    its('DisableHTTPPrinting') { should eq 1 }
  end
end

control 'windows-233' do
  title 'Ensure \'Turn off Registration if URL connection is referring to Microsoft.com\' is set to \'Enabled\''
  desc 'This policy setting specifies whether the Windows Registration Wizard connects to Microsoft.com for online registration.

  The recommended state for this setting is: Enabled.'
  impact 0.5
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.8.22.1.7'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.8.22.1.7'
  tag 'level': '2'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('This Control only executes if attribute(\'level_1_or_2\') is set to 2') do
    attribute('level_1_or_2') == 2
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Registration Wizard Control') do
    it { should exist }
    it { should have_property 'NoRegistration' }
    its('NoRegistration') { should eq 1 }
  end
end

control 'windows-234' do
  title 'Ensure \'Turn off Search Companion content file updates\' is set to \'Enabled\''
  desc 'This policy setting specifies whether Search Companion should automatically download content updates during local and Internet searches.

  The recommended state for this setting is: Enabled.'
  impact 0.5
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.8.22.1.8'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.8.22.1.8'
  tag 'level': '2'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('This Control only executes if attribute(\'level_1_or_2\') is set to 2') do
    attribute('level_1_or_2') == 2
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\SearchCompanion') do
    it { should exist }
    it { should have_property 'DisableContentFileUpdates' }
    its('DisableContentFileUpdates') { should eq 1 }
  end
end

control 'windows-235' do
  title 'Ensure \'Turn off the \'Order Prints\' picture task\' is set to \'Enabled\''
  desc 'This policy setting specifies whether the \'Order Prints Online\' task is available from Picture Tasks in Windows folders.

  The Order Prints Online Wizard is used to download a list of providers and allow users to order prints online.

  The recommended state for this setting is: Enabled.'
  impact 0.5
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.8.22.1.9'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.8.22.1.9'
  tag 'level': '2'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('This Control only executes if attribute(\'level_1_or_2\') is set to 2') do
    attribute('level_1_or_2') == 2
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer') do
    it { should exist }
    it { should have_property 'NoOnlinePrintsWizard' }
    its('NoOnlinePrintsWizard') { should eq 1 }
  end
end

control 'windows-236' do
  title 'Ensure \'Turn off the \'Publish to Web\' task for files and folders\' is set to \'Enabled\''
  desc 'This policy setting specifies whether the tasks Publish this file to the Web, Publish this folder to the Web, and Publish the selected items to the Web are available from File and Folder Tasks in Windows folders.

  The recommended state for this setting is: Enabled.'
  impact 0.5
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.8.22.1.10'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.8.22.1.10'
  tag 'level': '2'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('This Control only executes if attribute(\'level_1_or_2\') is set to 2') do
    attribute('level_1_or_2') == 2
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer') do
    it { should exist }
    it { should have_property 'NoPublishingWizard' }
    its('NoPublishingWizard') { should eq 1 }
  end
end

control 'windows-237' do
  title 'Ensure \'Turn off the Windows Messenger Customer Experience Improvement Program\' is set to \'Enabled\''
  desc 'This policy setting specifies whether Windows Messenger can collect anonymous information about how the Windows Messenger software and service is used. Microsoft uses information collected through the Customer Experience Improvement Program to detect software flaws so that they can be corrected more quickly, enabling this setting will reduce the amount of data Microsoft is able to gather for this purpose.

  The recommended state for this setting is: Enabled.'
  impact 0.5
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.8.22.1.11'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.8.22.1.11'
  tag 'level': '2'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('This Control only executes if attribute(\'level_1_or_2\') is set to 2') do
    attribute('level_1_or_2') == 2
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Messenger\\Client') do
    it { should exist }
    it { should have_property 'CEIP' }
    its('CEIP') { should eq 2 }
  end
end

control 'windows-238' do
  title 'Ensure \'Turn off Windows Customer Experience Improvement Program\' is set to \'Enabled\''
  desc 'This policy setting specifies whether Windows Messenger can collect anonymous information about how the Windows Messenger software and service is used.

  Microsoft uses information collected through the Windows Customer Experience Improvement Program to detect software flaws so that they can be corrected more quickly, enabling this setting will reduce the amount of data Microsoft is able to gather for this purpose. The recommended state for this setting is: Enabled.'
  impact 0.5
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.8.22.1.12'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.8.22.1.12'
  tag 'level': '2'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('This Control only executes if attribute(\'level_1_or_2\') is set to 2') do
    attribute('level_1_or_2') == 2
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\SQMClient\\Windows') do
    it { should exist }
    it { should have_property 'CEIPEnable' }
    its('CEIPEnable') { should eq 0 }
  end
end

control 'windows-239' do
  title 'Ensure \'Turn off Windows Error Reporting\' is set to \'Enabled\''
  desc 'This policy setting controls whether or not errors are reported to Microsoft.

  Error Reporting is used to report information about a system or application that has failed or has stopped responding and is used to improve the quality of the product.

  The recommended state for this setting is: Enabled.'
  impact 0.5
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.8.22.1.13'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.8.22.1.13'
  tag 'level': '2'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('This Control only executes if attribute(\'level_1_or_2\') is set to 2') do
    attribute('level_1_or_2') == 2
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Windows Error Reporting') do
    it { should exist }
    it { should have_property 'Disabled' }
    its('Disabled') { should eq 1 }
  end
end

control 'windows-240' do
  title 'Ensure \'Support device authentication using certificate\' is set to \'Enabled: Automatic\''
  desc 'This policy setting allows you to set support for Kerberos to attempt authentication using the certificate for the device to the domain.

  Support for device authentication using certificate will require connectivity to a DC in the device account domain which supports certificate authentication for computer accounts.

  The recommended state for this setting is: Enabled: Automatic.'
  impact 0.5
  tag 'windows': %w[2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.8.25.1'
  tag 'level': '2'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('Only for Windows Server 2016, 2019 and if attribute(\'level_1_or_2\') is set to 2') do
    (((os[:name].include? '2016') || (os[:name].include? '2019')) && attribute('level_1_or_2') == 2)
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\kerberos\\parameters') do
    it { should exist }
    it { should have_property 'DevicePKInitBehavior' }
    its('DevicePKInitBehavior') { should eq 0 }
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\kerberos\\parameters') do
    it { should exist }
    it { should have_property 'DevicePKInitEnabled' }
    its('DevicePKInitEnabled') { should eq 1 }
  end
end

control 'windows-241' do
  title 'Ensure \'Disallow copying of user input methods to the system account for sign-in\' is set to \'Enabled\''
  desc 'This policy prevents automatic copying of user input methods to the system account for use on the sign-in screen. The user is restricted to the set of input methods that are enabled in the system account.

  The recommended state for this setting is: Enabled.'
  impact 0.5
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.8.26.1'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.8.26.1'
  tag 'level': '2'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('This Control only executes if attribute(\'level_1_or_2\') is set to 2') do
    attribute('level_1_or_2') == 2
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Control Panel\\International') do
    it { should exist }
    it { should have_property 'BlockUserInputMethodsForSignIn' }
    its('BlockUserInputMethodsForSignIn') { should eq 1 }
  end
end

control 'windows-242' do
  title 'Ensure \'Block user from showing account details on signin\' is set to \'Enabled\''
  desc 'This policy prevents the user from showing account details (email address or user name) on the sign-in screen.

  The recommended state for this setting is: Enabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.8.27.1'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.8.27.1'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('This Control only executes if attribute(\'level_1_or_2\') is set to 2') do
    attribute('level_1_or_2') == 2
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\System') do
    it { should exist }
    it { should have_property 'BlockUserFromShowingAccountDetailsOnSignin' }
    its('BlockUserFromShowingAccountDetailsOnSignin') { should eq 1 }
  end
end

control 'windows-243' do
  title 'Ensure \'Do not enumerate connected users on domain-joined computers\' is set to \'Enabled\''
  desc 'This policy setting prevents connected users from being enumerated on domain-joined computers.

  The recommended state for this setting is: Enabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.8.27.2'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.8.27.2'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('This Control only executes if attribute(\'level_1_or_2\') is set to 2') do
    attribute('level_1_or_2') == 2
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\System') do
    it { should exist }
    it { should have_property 'DontDisplayNetworkSelectionUI' }
    its('DontDisplayNetworkSelectionUI') { should eq 1 }
  end
end

control 'windows-244' do
  title 'Ensure \'Do not enumerate connected users on domain-joined computers\' is set to \'Enabled\''
  desc 'This policy setting prevents connected users from being enumerated on domain-joined computers.

  The recommended state for this setting is: Enabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.8.27.3'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.8.27.3'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('This Control only executes if attribute(\'level_1_or_2\') is set to 2') do
    attribute('level_1_or_2') == 2
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\System') do
    it { should exist }
    it { should have_property 'DontEnumerateConnectedUsers' }
    its('DontEnumerateConnectedUsers') { should eq 1 }
  end
end

control 'windows-245' do
  title 'Ensure \'Enumerate local users on domain-joined computers\' is set to \'Disabled\' (MS only)'
  desc 'This policy setting allows local users to be enumerated on domain-joined computers.

  The recommended state for this setting is: Disabled.'
  impact 1.0
  tag 'windows': %w[2016 2019]
  tag 'profile': ['Member Server']
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.8.27.4'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  nly_if('Only for Windows Server 2016, 2019 and if attribute(\'ms_or_dc\') is set to MS') do
    (((os[:name].include? '2016') || (os[:name].include? '2019')) && attribute('ms_or_dc') == 'MS')
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\System') do
    it { should exist }
    it { should have_property 'EnumerateLocalUsers' }
    its('EnumerateLocalUsers') { should eq 0 }
  end
end

control 'windows-246' do
  title 'Ensure \'Turn off app notifications on the lock screen\' is set to \'Enabled\''
  desc 'This policy setting allows you to prevent app notifications from appearing on the lock screen.

  The recommended state for this setting is: Enabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.8.27.4'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.8.27.5'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\System') do
    it { should exist }
    it { should have_property 'DisableLockScreenAppNotifications' }
    its('DisableLockScreenAppNotifications') { should eq 1 }
  end
end

control 'windows-247' do
  title 'Ensure \'Turn off picture password sign-in\' is set to \'Enabled\''
  desc 'This policy setting allows you to control whether a domain user can sign in using a picture password.

  The recommended state for this setting is: Enabled.

  **Note:** If the picture password feature is permitted, the user\'s domain password is cached in the system vault when using it.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.8.27.5'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.8.27.6'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\System') do
    it { should exist }
    it { should have_property 'AllowDomainPINLogon' }
    its('AllowDomainPINLogon') { should eq 0 }
  end
end

control 'windows-248' do
  title 'Ensure \'Turn on convenience PIN sign-in\' is set to \'Disabled\''
  desc 'This policy setting allows you to control whether a domain user can sign in using a convenience PIN. In Windows 10, convenience PIN was replaced with Passport, which has stronger security properties. To configure Passport for domain users, use the policies under Computer Configuration\\Administrative Templates\\Windows Components\\Microsoft Passport for Work.

  **Note:** The user\'s domain password will be cached in the system vault when using this feature.

  The recommended state for this setting is: Disabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.8.27.6'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.8.27.7'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\System') do
    it { should exist }
    it { should have_property 'AllowDomainPINLogon' }
    its('AllowDomainPINLogon') { should eq 0 }
  end
end

control 'windows-249' do
  title 'Ensure \'Untrusted Font Blocking\' is set to \'Enabled: Block untrusted fonts and log events\''
  desc 'This security feature provides a global setting to prevent programs from loading untrusted fonts. Untrusted fonts are any font installed outside of the %windir%\Fonts directory. This feature can be configured to be in 3 modes: On, Off, and Audit.

  The recommended state for this setting is: Enabled: Block untrusted fonts and log events '
  impact 1.0
  tag 'windows': %w[2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.8.28.1'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('Only for Windows Server 2016, 2019') do
    ((os[:name].include? '2016') || (os[:name].include? '2019'))
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\MitigationOptions') do
    it { should exist }
    it { should have_property 'MitigationOptions_FontBocking' }
    its('MitigationOptions_FontBocking') { should eq '1000000000000' }
  end
end

control 'windows-250' do
  title 'Ensure \'Require a password when a computer wakes (on battery)\' is set to \'Enabled\''
  desc 'Specifies whether or not the user is prompted for a password when the system resumes from sleep.

  The recommended state for this setting is: Enabled.'
  impact 0.5
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.8.33.6.1'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.8.33.6.1'
  tag 'level': '2'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('This Control only executes if attribute(\'level_1_or_2\') is set to 2') do
    attribute('level_1_or_2') == 2
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Power\\PowerSettings\\f15576e8-98b7-4186-b944-eafa664402d9') do
    it { should exist }
    it { should have_property 'DCSettingIndex' }
    its('DCSettingIndex') { should eq 0 }
  end
end

control 'windows-251' do
  title 'Ensure \'Require a password when a computer wakes (plugged in)\' is set to \'Enabled\''
  desc 'Specifies whether or not the user is prompted for a password when the system resumes from sleep.

  The recommended state for this setting is: Enabled.'
  impact 0.5
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.8.33.6.2'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.8.33.6.2'
  tag 'level': '2'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('This Control only executes if attribute(\'level_1_or_2\') is set to 2') do
    attribute('level_1_or_2') == 2
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Power\\PowerSettings\\f15576e8-98b7-4186-b944-eafa664402d9') do
    it { should exist }
    it { should have_property 'ACSettingIndex' }
    its('ACSettingIndex') { should eq 0 }
  end
end

control 'windows-252' do
  title 'Ensure \'Require a password when a computer wakes (on battery)\' is set to \'Enabled\''
  desc 'Specifies whether or not the user is prompted for a password when the system resumes from sleep.

  The recommended state for this setting is: Enabled.'
  impact 1.0
  tag 'windows': %w[2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.8.33.6.3'
  tag 'level': '2'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('Only for Windows Server 2016, 2019 and if attribute(\'level_1_or_2\') is set to 2') do
    (((os[:name].include? '2016') || (os[:name].include? '2019')) && attribute('level_1_or_2') == 2)
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Power\\PowerSettings\\0e796bdb-100d-47d6-a2d5-f7d2daa51f51') do
    it { should exist }
    it { should have_property 'DCSettingIndex' }
    its('DCSettingIndex') { should eq 1 }
  end
end

control 'windows-253' do
  title 'Ensure \'Require a password when a computer wakes (plugged in)\' is set to \'Enabled\''
  desc 'Specifies whether or not the user is prompted for a password when the system resumes from sleep.

  The recommended state for this setting is: Enabled.'
  impact 1.0
  tag 'windows': %w[2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.8.33.6.4'
  tag 'level': '2'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('Only for Windows Server 2016, 2019 and if attribute(\'level_1_or_2\') is set to 2') do
    (((os[:name].include? '2016') || (os[:name].include? '2019')) && attribute('level_1_or_2') == 2)
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Power\\PowerSettings\\0e796bdb-100d-47d6-a2d5-f7d2daa51f51') do
    it { should exist }
    it { should have_property 'ACSettingIndex' }
    its('ACSettingIndex') { should eq 1 }
  end
end

control 'windows-254' do
  title 'Ensure \'Configure Offer Remote Assistance\' is set to \'Disabled\''
  desc 'This policy setting allows you to turn on or turn off Offer (Unsolicited) Remote Assistance on this computer.

  Help desk and support personnel will not be able to proactively offer assistance, although they can still respond to user assistance requests.

  The recommended state for this setting is: Disabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.8.35.1'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.8.35.1'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\policies\\Microsoft\\Windows NT\\Terminal Services') do
    it { should exist }
    it { should have_property 'fAllowUnsolicited' }
    its('fAllowUnsolicited') { should eq 0 }
  end
end

control 'windows-255' do
  title 'Ensure \'Configure Solicited Remote Assistance\' is set to \'Disabled\''
  desc 'This policy setting allows you to turn on or turn off Solicited (Ask for) Remote Assistance on this computer.

  The recommended state for this setting is: Disabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.8.35.2'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.8.35.2'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\policies\\Microsoft\\Windows NT\\Terminal Services') do
    it { should exist }
    it { should have_property 'fAllowToGetHelp' }
    its('fAllowToGetHelp') { should eq 0 }
  end
end

control 'windows-256' do
  title 'Ensure \'Enable RPC Endpoint Mapper Client Authentication\' is set to \'Enabled\' (MS only)'
  desc 'This policy setting controls whether RPC clients authenticate with the Endpoint Mapper Service when the call they are making contains authentication information. The Endpoint Mapper Service on computers running Windows NT4 (all service packs) cannot process authentication information supplied in this manner. This policy setting can cause a specific issue with **1-way** forest trusts if it is applied to the **trusting** domain DCs (see Microsoft [KB3073942](https://support.microsoft.com/en-us/kb/3073942)), so we do not recommend applying it to Domain Controllers.

  **Note:** This policy will not be in effect until the system is rebooted.

  The recommended state for this setting is: Enabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.8.36.1'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.8.36.1'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('This Control only executes if attribute(\'ms_or_dc\') is set to MS') do
    attribute('ms_or_dc') == 'MS'
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows NT\\Rpc') do
    it { should exist }
    it { should have_property 'EnableAuthEpResolution' }
    its('EnableAuthEpResolution') { should eq 1 }
  end
end

control 'windows-257' do
  title 'Ensure \'Restrict Unauthenticated RPC clients\' is set to \'Enabled: Authenticated\' (MS only)'
  desc 'This policy setting controls how the RPC server runtime handles unauthenticated RPC clients connecting to RPC servers.

  This policy setting impacts all RPC applications. In a domain environment this policy setting should be used with caution as it can impact a wide range of functionality including group policy processing itself. Reverting a change to this policy setting can require manual intervention on each affected machine. **This policy setting should never be applied to a Domain Controller.**

  A client will be considered an authenticated client if it uses a named pipe to communicate with the server or if it uses RPC Security. RPC Interfaces that have specifically requested to be accessible by unauthenticated clients may be exempt from this restriction, depending on the selected value for this policy setting.

  -- **None** allows all RPC clients to connect to RPC Servers running on the machine on which the policy setting is applied.

  -- **Authenticated** allows only authenticated RPC Clients (per the definition above) to connect to RPC Servers running on the machine on which the policy setting is applied. Exemptions are granted to interfaces that have requested them.

  -- **Authenticated without exceptions** allows only authenticated RPC Clients (per the definition above) to connect to RPC Servers running on the machine on which the policy setting is applied. No exceptions are allowed. **This value has the potential to cause serious problems and is not recommended.**

  **Note:** This policy setting will not be applied until the system is rebooted.

  The recommended state for this setting is: Enabled: Authenticated.'
  impact 0.5
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.8.36.2'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.8.36.2'
  tag 'level': '2'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('This Control only executes if attribute(\'level_1_or_2\') is set to 2 and attribute(\'ms_or_dc\') is set to MS') do
    ((attribute('level_1_or_2') == 2) && (attribute('ms_or_dc') == 'MS'))
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows NT\\Rpc') do
    it { should exist }
    it { should have_property 'RestrictRemoteClients' }
    its('RestrictRemoteClients') { should eq 1 }
  end
end

control 'windows-258' do
  title 'Ensure \'Microsoft Support Diagnostic Tool: Turn on MSDT interactive communication with support provider\' is set to \'Disabled\''
  desc ' This policy setting configures Microsoft Support Diagnostic Tool (MSDT) interactive communication with the support provider. MSDT gathers diagnostic data for analysis by support professionals.

  The recommended state for this setting is: Disabled.'
  impact 0.5
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.8.44.5.1'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.8.44.5.1'
  tag 'level': '2'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('This Control only executes if attribute(\'level_1_or_2\') is set to 2') do
    attribute('level_1_or_2') == 2
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\ScriptedDiagnosticsProvider\\Policy') do
    it { should exist }
    it { should have_property 'DisableQueryRemoteServer' }
    its('DisableQueryRemoteServer') { should eq 0 }
  end
end

control 'windows-259' do
  title 'Ensure \'Enable/Disable PerfTrack\' is set to \'Disabled\''
  desc 'This policy setting specifies whether to enable or disable tracking of responsiveness events.

  The recommended state for this setting is: Disabled.'
  impact 0.5
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.8.44.11.1'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.8.44.11.1'
  tag 'level': '2'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('This Control only executes if attribute(\'level_1_or_2\') is set to 2') do
    attribute('level_1_or_2') == 2
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WDI\\{9c5a40da-b965-4fc3-8781-88dd50a6299d}') do
    it { should exist }
    it { should have_property 'ScenarioExecutionEnabled' }
    its('ScenarioExecutionEnabled') { should eq 0 }
  end
end

control 'windows-260' do
  title 'Ensure \'Turn off the advertising ID\' is set to \'Enabled\''
  desc 'This policy setting turns off the advertising ID, preventing apps from using the ID for experiences across apps.

  The recommended state for this setting is: Enabled.'
  impact 0.5
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.8.46.1'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.8.46.1'
  tag 'level': '2'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('This Control only executes if attribute(\'level_1_or_2\') is set to 2') do
    attribute('level_1_or_2') == 2
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\policies\\Microsoft\\Windows\\AdvertisingInfo') do
    it { should exist }
    it { should have_property 'DisabledByGroupPolicy' }
    its('DisabledByGroupPolicy') { should eq 1 }
  end
end

control 'windows-261' do
  title 'Ensure \'Enable Windows NTP Client\' is set to \'Enabled\''
  desc 'This policy setting specifies whether the Windows NTP Client is enabled. Enabling the Windows NTP Client allows your computer to synchronize its computer clock with other NTP servers. You might want to disable this service if you decide to use a third-party time provider.

  The recommended state for this setting is: Enabled.'
  impact 0.5
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.8.49.1.1'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.8.49.1.1'
  tag 'level': '2'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('This Control only executes if attribute(\'level_1_or_2\') is set to 2') do
    attribute('level_1_or_2') == 2
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\W32Time\\TimeProviders\\NtpClient') do
    it { should exist }
    it { should have_property 'Enabled' }
    its('Enabled') { should eq 1 }
  end
end

control 'windows-262' do
  title 'Ensure \'Enable Windows NTP Server\' is set to \'Disabled\' (MS only)'
  desc 'This policy setting allows you to specify whether the Windows NTP Server is enabled.

  The recommended state for this setting is: Disabled.'
  impact 0.5
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.8.49.1.2'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.8.49.1.2'
  tag 'level': '2'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('This Control only executes if attribute(\'level_1_or_2\') is set to 2 and attribute(\'ms_or_dc\') is set to MS') do
    ((attribute('level_1_or_2') == 2) && (attribute('ms_or_dc') == 'MS'))
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\W32Time\\TimeProviders\\NtpServer') do
    it { should exist }
    it { should have_property 'Enabled' }
    its('Enabled') { should eq 0 }
  end
end

control 'windows-263' do
  title 'Ensure \'Allow a Windows app to share application data between users\' is set to \'Disabled\''
  desc 'Manages a Windows app\'s ability to share data between users who have installed the app. Data is shared through the SharedLocal folder. This folder is available through the Windows.Storage API.

  The recommended state for this setting is: Disabled.'
  impact 0.5
  tag 'windows': %w[2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.9.4.1'
  tag 'level': '2'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('Only for Windows Server 2016, 2019 and if attribute(\'level_1_or_2\') is set to 2') do
    (((os[:name].include? '2016') || (os[:name].include? '2019')) && attribute('level_1_or_2') == 2)
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\AppModel\\StateManager') do
    it { should exist }
    it { should have_property 'AllowSharedLocalAppData' }
    its('AllowSharedLocalAppData') { should eq 0 }
  end
end

control 'windows-264' do
  title 'Ensure \'Allow Microsoft accounts to be optional\' is set to \'Enabled\''
  desc 'This policy setting lets you control whether Microsoft accounts are optional for Windows Store apps that require an account to sign in. This policy only affects Windows Store apps that support it.

  The recommended state for this setting is: Enabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.9.6.1'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.9.6.1'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('Only for Windows Server 2012') do
    os[:name].include? '2012'
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System') do
    it { should exist }
    it { should have_property 'MSAOptional' }
    its('MSAOptional') { should eq 1 }
  end
end

control 'windows-265' do
  title 'Ensure \'Set the default behavior for AutoRun\' is set to \'Enabled: Do not execute any autorun commands\''
  desc 'This policy setting sets the default behavior for Autorun commands. Autorun commands are generally stored in autorun.inf files. They often launch the installation program or other routines.

  The recommended state for this setting is: Enabled: Do not execute any autorun commands.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.9.8.1'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.9.8.1'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Explorer') do
    it { should exist }
    it { should have_property 'NoAutoplayfornonVolume' }
    its('NoAutoplayfornonVolume') { should eq 1 }
  end
end

control 'windows-266' do
  title 'Ensure \'Set the default behavior for AutoRun\' is set to \'Enabled: Do not execute any autorun commands\''
  desc 'This policy setting sets the default behavior for Autorun commands. Autorun commands are generally stored in autorun.inf files. They often launch the installation program or other routines.

  The recommended state for this setting is: Enabled: Do not execute any autorun commands.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.9.8.2'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.9.8.2'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer') do
    it { should exist }
    it { should have_property 'NoAutorun' }
    its('NoAutorun') { should eq 1 }
  end
end

control 'windows-267' do
  title 'Ensure \'Turn off Autoplay\' is set to \'Enabled: All drives\''
  desc 'Autoplay starts to read from a drive as soon as you insert media in the drive, which causes the setup file for programs or audio media to start immediately. An attacker could use this feature to launch a program to damage the computer or data on the computer. Autoplay is disabled by default on some removable drive types, such as floppy disk and network drives, but not on CD-ROM drives.

  **Note:** You cannot use this policy setting to enable Autoplay on computer drives in which it is disabled by default, such as floppy disk and network drives.

  The recommended state for this setting is: Enabled: All drives.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.9.8.3'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.9.8.3'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration', 'SYS.1.2.2.M5', 'Schutz vor Schadsoftware']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer') do
    it { should exist }
    it { should have_property 'NoDriveTypeAutoRun' }
    its('NoDriveTypeAutoRun') { should eq 255 }
  end
end

control 'windows-268' do
  title 'Ensure \'Configure enhanced anti-spoofing\' is set to \'Enabled\''
  desc 'This policy setting determines whether enhanced anti-spoofing is configured for devices which support it.

  The recommended state for this setting is: Enabled. '
  impact 1.0
  tag 'windows': %w[2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.9.10.1.1'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('Only for Windows Server 2016, 2019') do
    ((os[:name].include? '2016') || (os[:name].include? '2019'))
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Biometrics\\FacialFeatures') do
    it { should exist }
    it { should have_property 'EnhancedAntiSpoofing' }
    its('EnhancedAntiSpoofing') { should eq 1 }
  end
end

control 'windows-269' do
  title 'Ensure \'Allow Use of Camera\' is set to \'Disabled\''
  desc 'This policy setting controls whether the use of Camera devices on the machine are permitted.
  The recommended state for this setting is: Disabled.'
  impact 0.5
  tag 'windows': %w[2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.9.12.1'
  tag 'level': '2'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('Only for Windows Server 2016, 2019 and if attribute(\'level_1_or_2\') is set to 2') do
    (((os[:name].include? '2016') || (os[:name].include? '2019')) && attribute('level_1_or_2') == 2)
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Camera') do
    it { should exist }
    it { should have_property 'AllowCamera' }
    its('AllowCamera') { should eq 0 }
  end
end

control 'windows-270' do
  title 'Ensure \'Turn off Microsoft consumer experiences\' is set to \'Enabled\''
  desc 'This policy setting turns off experiences that help consumers make the most of their devices and Microsoft account.
  The recommended state for this setting is: Enabled.

  Note: Per Microsoft TechNet, this policy setting only applies to Windows 10 Enterprise and Windows 10 Education editions.'
  impact 1.0
  tag 'windows': %w[2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.9.13.1'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('Only for Windows Server 2016, 2019') do
    ((os[:name].include? '2016') || (os[:name].include? '2019'))
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\CloudContent') do
    it { should exist }
    it { should have_property 'DisableWindowsConsumerFeatures' }
    its('DisableWindowsConsumerFeatures') { should eq 1 }
  end
end

control 'windows-271' do
  title 'Ensure \'Require pin for pairing\' is set to \'Enabled\''
  desc 'This policy setting controls whether or not a PIN is required for pairing to a wireless display device.

  The recommended state for this setting is: Enabled.'
  impact 1.0
  tag 'windows': %w[2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.9.14.1'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('Only for Windows Server 2016, 2019') do
    ((os[:name].include? '2016') || (os[:name].include? '2019'))
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Connect') do
    it { should exist }
    it { should have_property 'RequirePinForPairing' }
    its('RequirePinForPairing') { should eq 1 }
  end
end

control 'windows-272' do
  title 'Ensure \'Do not display the password reveal button\' is set to \'Enabled\''
  desc 'This policy setting allows you to configure the display of the password reveal button in password entry user experiences.

  The recommended state for this setting is: Enabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.9.15.1'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.9.15.1'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M3', 'Sichere Administration', 'SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\CredUI') do
    it { should exist }
    it { should have_property 'DisablePasswordReveal' }
    its('DisablePasswordReveal') { should eq 1 }
  end
end

control 'windows-273' do
  title 'Ensure \'Enumerate administrator accounts on elevation\' is set to \'Disabled\''
  desc 'This policy setting controls whether administrator accounts are displayed when a user attempts to elevate a running application.

  The recommended state for this setting is: Disabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.9.15.2'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.9.15.2'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\CredUI') do
    it { should exist }
    it { should have_property 'EnumerateAdministrators' }
    its('EnumerateAdministrators') { should eq 0 }
  end
end

control 'windows-274' do
  title 'Ensure \'Allow Telemetry\' is set to \'Enabled: 0 - Security [Enterprise Only]\' or \'Enabled: 1 - Basic\''
  desc 'This policy setting determines the amount of diagnostic and usage data reported to Microsoft.

  A value of 0 will send minimal data to Microsoft. This data includes Malicious Software Removal Tool (MSRT)  Windows Defender data, if enabled, and telemetry client settings. Setting a value of 0 applies to enterprise, EDU, IoT and server devices only. Setting a value of 0 for other devices is equivalent to choosing a value of 1. A value of 1 sends only a basic amount of diagnostic and usage data. Note that setting values of 0 or 1 will degrade certain experiences on the device. A value of 2 sends enhanced diagnostic and usage data. A value of 3 sends the same data as a value of 2, plus additional diagnostics data, including the files and content that may have caused the problem. Windows 10 telemetry settings apply to the Windows operating system and some first party apps. This setting does not apply to third party apps running on Windows 10.

  The recommended state for this setting is: Enabled: 0 - Security [Enterprise Only].

  **Note:** If the \'Allow Telemetry\' setting is configured to \'0 - Security [Enterprise Only]\', then the options in Windows Update to defer upgrades and updates will have no effect.'
  impact 1.0
  tag 'windows': %w[2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.9.16.1'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('Only for Windows Server 2016, 2019') do
    ((os[:name].include? '2016') || (os[:name].include? '2019'))
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\DataCollection') do
    it { should exist }
    it { should have_property 'AllowTelemetry' }
    its('AllowTelemetry') { should eq 0 }
  end
end

control 'windows-275' do
  title 'Ensure \'Configure Authenticated Proxy usage for the Connected User Experience and Telemetry service\' is set to \'Enabled: Disable Authenticated Proxy usage\''
  desc 'This policy setting controls whether the Connected User Experience and Telemetry service can automatically use an authenticated proxy to send data back to Microsoft.
  The recommended state for this setting is: Enabled: Disable Authenticated Proxy usage.'
  impact 0.5
  tag 'windows': %w[2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.9.16.2'
  tag 'level': '2'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('Only for Windows Server 2016, 2019 and if attribute(\'level_1_or_2\') is set to 2') do
    (((os[:name].include? '2016') || (os[:name].include? '2019')) && attribute('level_1_or_2') == 2)
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection') do
    it { should exist }
    it { should have_property 'DisableEnterpriseAuthProxy' }
    its('DisableEnterpriseAuthProxy') { should eq 1 }
  end
end

control 'windows-276' do
  title 'Ensure \'Disable pre-release features or settings\' is set to \'Disabled\''
  desc 'This policy setting determines the level that Microsoft can experiment with the product to study user preferences or device behavior. A value of 1 permits Microsoft to configure device settings only. A value of 2 allows Microsoft to conduct full experimentations.

  The recommended state for this setting is: Disabled.'
  impact 1.0
  tag 'windows': %w[2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.9.16.3'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('Only for Windows Server 2016, 2019') do
    ((os[:name].include? '2016') || (os[:name].include? '2019'))
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\PreviewBuilds') do
    it { should exist }
    it { should have_property 'EnableConfigFlighting' }
    its('EnableConfigFlighting') { should eq 0 }
  end
end

control 'windows-277' do
  title 'Ensure \'Do not show feedback notifications\' is set to \'Enabled\''
  desc 'This policy setting allows an organization to prevent its devices from showing feedback questions from Microsoft.

  The recommended state for this setting is: Enabled.'
  impact 1.0
  tag 'windows': %w[2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.9.16.4'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('Only for Windows Server 2016, 2019') do
    ((os[:name].include? '2016') || (os[:name].include? '2019'))
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection') do
    it { should exist }
    it { should have_property 'DoNotShowFeedbackNotifications' }
    its('DoNotShowFeedbackNotifications') { should eq 1 }
  end
end

control 'windows-278' do
  title 'Ensure \'Toggle user control over Insider builds\' is set to \'Disabled\''
  desc 'This policy setting determines whether users can access the Insider build controls in the Advanced Options for Windows Update. These controls are located under \'Get Insider builds,\' and enable users to make their devices available for downloading and installing Windows preview software.

  The recommended state for this setting is: Disabled.

  **Note:** This policy setting applies only to devices running Windows 10 Pro, Windows 10 Enterprise, or Server 2016.'
  impact 1.0
  tag 'windows': %w[2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.9.16.5'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('Only for Windows Server 2016, 2019') do
    ((os[:name].include? '2016') || (os[:name].include? '2019'))
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\PreviewBuilds') do
    it { should exist }
    it { should have_property 'AllowBuildPreview' }
    its('AllowBuildPreview') { should eq 0 }
  end
end

control 'windows-279' do
  title 'Ensure \'EMET 5.52\' or higher is installed'
  desc 'The Enhanced Mitigation Experience Toolkit (EMET) is free and supported security software developed by Microsoft that allows an enterprise to apply exploit mitigations to applications that run on Windows. Many of these mitigations were later coded directly into Windows 10 and Server 2016.

  More information on EMET, including download and User Guide, can be obtained here:
  Enhanced Mitigation Experience Toolkit - EMET - TechNet Security

  Note: Although EMET is quite effective at enhancing exploit protection on Windows server OSes prior to Server 2016, it is highly recommended that compatibility testing is done on typical server configurations (including all CIS-recommended EMET settings) before widespread deployment to your environment.

  Note #2: Microsoft has announced that EMET will be End-Of-Life (EOL) on July 31, 2018. This does not mean the software will stop working, only that Microsoft will not update it any further past that date, nor troubleshoot new problems with it. They are instead recommending that servers be upgraded to Server 2016.
  Note #3: EMET has been reported to be very problematic on 32-bit OSes - we only recommend using it with 64-bit OSes.'
  impact 1.0
  tag 'windows': %w[2012R2]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.9.24.1'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('Only for Windows Server 2012') do
    os[:name].include? '2012'
  end
  describe package('EMET*').version do
    it { should be_installed }
    its('version') { should cmp >= '5.51' }
  end
  describe registry_key('HKLM:\\SYSTEM\\CurrentControlSet\\services\\EMET_Service') do
    it { should exist }
    it { should have_property 'Start' }
    its('Start') { should cmp == 2 }
  end
end

control 'windows-280' do
  title 'Ensure \'Default Action and Mitigation Settings\' is set to \'Enabled\' (plus subsettings)'
  desc 'This setting configures the default action after detection and advanced ROP mitigation.

  The recommended state for this setting is:
  - Default Action and Mitigation Settings - Enabled
  - Deep Hooks - Enabled
  - Anti Detours - Enabled
  - Banned Functions - Enabled
  - Exploit Action -User Configured'
  impact 1.0
  tag 'windows': %w[2012R2]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.9.24.2'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('Only for Windows Server 2012') do
    os[:name].include? '2012'
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\EMET\\SysSettings') do
    it { should exist }
    it { should have_property 'AntiDetours' }
    it { should have_property 'BannedFunctions' }
    it { should have_property 'DeepHooks' }
    it { should have_property 'ExploitAction' }
    its('AntiDetours') { should eq 1 }
    its('BannedFunctions') { should eq 1 }
    its('DeepHooks') { should eq 1 }
    its('ExploitAction') { should eq 2 }
  end
end

control 'windows-281' do
  title 'Ensure \'Default Protections for Internet Explorer\' is set to \'Enabled\''
  desc 'This setting determines if recommended EMET mitigations are applied to Internet Explorer.

  The recommended state for this setting is: Enabled.'
  impact 1.0
  tag 'windows': %w[2012R2]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.9.24.3'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('Only for Windows Server 2012') do
    os[:name].include? '2012'
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\EMET\\Defaults\\IE') do
    it { should exist }
    it { should have_property 'AntiDetours' }
    its('AntiDetours') { should eq 1 }
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\Defaults') do
    it { should exist }
    it { should have_property 'IE' }
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\Defaults') do
    it { should exist }
    it { should have_property '*\\Internet Explorer\\iexplore.exe' }
    its(['*\\Internet Explorer\\iexplore.exe']) { should eq '+EAF+ eaf_modules:mshtml.dll;flash*.ocx;jscript*.dll;vbscript.dll;vgx.dll +ASR asr_modules:npjpi*.dll;jp2iexp.dll;vgx.dll;msxml4*.dll;wshom.ocx;scrrun.dll;vbscript.dll asr_zones:1;2' }
  end
end

control 'windows-282' do
  title 'Ensure \'Default Protections for Popular Software\' is set to \'Enabled\''
  desc 'This setting determines if recommended EMET mitigations are applied to the following popular software:
  - 7-Zip
  - Adobe Photoshop
  - Foxit Reader
  - Google Chrome
  - Google Talk
  - iTunes
  - Microsoft Live Writer
  - Microsoft Lync Communicator
  - Microsoft Photo Gallery
  - Microsoft SkyDrive
  - mIRC
  - Mozilla Firefox
  - Mozilla Thunderbird
  - Opera
  - Pidgin
  - QuickTime Player
  - RealPlayer
  - Safari
  - Skype
  - VideoLAN VLC
  - Winamp
  - Windows Live Mail
  - Windows Media Player
  - WinRAR
  - WinZip
  The recommended state for this setting is: Enabled.'
  impact 1.0
  tag 'windows': %w[2012R2]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.9.24.4'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('Only for Windows Server 2012') do
    os[:name].include? '2012'
  end
  describe powershell('c:\\\'Program Files (x86)\'\\\'EMET 5.5\'\\EMET_Conf.exe --list') do
    its('stderr') { should eq '' }
    its('stdout') { should match(/^7z\.exe\s+\*\\7-Zip\s+(\S+\s?){2,14}$/) }
    its('stdout') { should match(/^7zFM\.exe\s+\*\\7-Zip\s+(\S+\s?){2,14}$/) }
    its('stdout') { should match(/^7zG\.exe\s+\*\\7-Zip\s+(\S+\s?){2,14}$/) }
    its('stdout') { should match(/^chrome\.exe\s+\*\\Google\\Chrome\\Application\s+(\S+\s?){2,14}$/) }
    its('stdout') { should match(/^firefox\.exe\s+\*\\Mozilla Firefox\s+(\S+\s?){2,14}$/) }
    its('stdout') { should match(/^Foxit Reader\.exe\s+\*\\Foxit Reader\s+(\S+\s?){2,14}$/) }
    its('stdout') { should match(/^googletalk\.exe\s+\*\\Google\\Google Talk\s+(\S+\s?){2,14}$/) }
    its('stdout') { should match(/^iTunes\.exe\s+\*\\iTunes\s+(\S+\s?){2,14}$/) }
    its('stdout') { should match(/^LYNC\.EXE\s+\*\\OFFICE1\*\s+(\S+\s?){2,14}$/) }
    its('stdout') { should match(/^mirc\.exe\s+\*\\mIRC\s+(\S+\s?){2,14}$/) }
    its('stdout') { should match(/^opera\.exe\s+\*\\Opera\\\*\s+(\S+\s?){2,14}$/) }
    its('stdout') { should match(/^opera\.exe\s+\*\\Opera\s+(\S+\s?){2,14}$/) }
    its('stdout') { should match(/^Photoshop\.exe\s+\*\\Adobe\\Adobe Photoshop CS\*\s+(\S+\s?){2,14}$/) }
    its('stdout') { should match(/^pidgin\.exe\s+\*\\Pidgin\s+(\S+\s?){2,14}$/) }
    its('stdout') { should match(/^plugin-container\.exe\s+\*\\Mozilla Firefox\s+(\S+\s?){2,14}$/) }
    its('stdout') { should match(/^plugin-container\.exe\s+\*\\Mozilla Thunderbird\s+(\S+\s?){2,14}$/) }
    its('stdout') { should match(/^QuickTimePlayer\.exe\s+\*\\QuickTime\s+(\S+\s?){2,14}$/) }
    its('stdout') { should match(/^rar\.exe\s+\*\\WinRAR\s+(\S+\s?){2,14}$/) }
    its('stdout') { should match(/^realconverter\.exe\s+\*\\Real\\RealPlayer\s+(\S+\s?){2,14}$/) }
    its('stdout') { should match(/^realplay\.exe\s+\*\\Real\\RealPlayer\s+(\S+\s?){2,14}$/) }
    its('stdout') { should match(/^Safari\.exe\s+\*\\Safari\s+(\S+\s?){2,14}$/) }
    its('stdout') { should match(/^SkyDrive\.exe\s+\*\\SkyDrive\s+(\S+\s?){2,14}$/) }
    its('stdout') { should match(/^Skype\.exe\s+\*\\Skype\\Phone\s+(\S+\s?){2,14}$/) }
    its('stdout') { should match(/^thunderbird\.exe\s+\*\\Mozilla Thunderbird\s+(\S+\s?){2,14}$/) }
    its('stdout') { should match(/^unrar\.exe\s+\*\\WinRAR\s+(\S+\s?){2,14}$/) }
    its('stdout') { should match(/^vlc\.exe\s+\*\\VideoLAN\\VLC\s+(\S+\s?){2,14}$/) }
    its('stdout') { should match(/^winamp\.exe\s+\*\\Winamp\s+(\S+\s?){2,14}$/) }
    its('stdout') { should match(/^winrar\.exe\s+\*\\WinRAR\s+(\S+\s?){2,14}$/) }
    its('stdout') { should match(/^winzip32\.exe\s+\*\\WinZip\s+(\S+\s?){2,14}$/) }
    its('stdout') { should match(/^winzip64\.exe\s+\*\\WinZip\s+(\S+\s?){2,14}$/) }
    its('stdout') { should match(/^WLXPhotoGallery\.exe\s+\*\\Windows Live\\Photo Gallery\s+(\S+\s?){2,14}$/) }
    its('stdout') { should match(/^wmplayer\.exe\s+\*\\Windows Media Player\s+(\S+\s?){2,14}$/) }
  end
end

control 'windows-283' do
  title 'Ensure \'Default Protections for Recommended Software\' is set to \'Enabled\''
  desc 'This setting determines if recommended EMET mitigations are applied to the following software:

  * Adobe Acrobat
  * Adobe Acrobat Reader
  * Microsoft Office suite applications
  * Oracle Java
  * WordPad
  The recommended state for this setting is: Enabled.'
  impact 1.0
  tag 'windows': %w[2012R2]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.9.24.5'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('Only for Windows Server 2012') do
    os[:name].include? '2012'
  end
  describe powershell('c:\\\'Program Files (x86)\'\\\'EMET 5.5\'\\EMET_Conf.exe --list') do
    its('stderr') { should eq '' }
    its('stdout') { should match(/^Acrobat\.exe\s+\*\\Adobe\\Acrobat\*\\Acrobat\s+(\S+\s?){2,14}$/) }
    its('stdout') { should match(/^AcroRd32\.exe\s+\*\\Adobe\\\*\\Reader\s+(\S+\s?){2,14}$/) }
    its('stdout') { should match(/^communicator\.exe\s+\*\\Microsoft Lync\s+(\S+\s?){2,14}$/) }
    its('stdout') { should match(/^EXCEL\.EXE\s+\*\\OFFICE1\*\s+(\S+\s?){2,14}$/) }
    its('stdout') { should match(/^iexplore\.exe\s+\*\\Internet Explorer\s+(\S+\s?){2,14}$/) }
    its('stdout') { should match(/^INFOPATH\.EXE\s+\*\\OFFICE1\*\s+(\S+\s?){2,14}$/) }
    its('stdout') { should match(/^java\.exe\s+\*\\Java\\jre\*\\bin\s+(\S+\s?){2,14}$/) }
    its('stdout') { should match(/^javaw\.exe\s+\*\\Java\\jre\*\\bin\s+(\S+\s?){2,14}$/) }
    its('stdout') { should match(/^javaws\.exe\s+\*\\Java\\jre\*\\bin\s+(\S+\s?){2,14}$/) }
    its('stdout') { should match(/^MSACCESS\.EXE\s+\*\\OFFICE1\*\s+(\S+\s?){2,14}$/) }
    its('stdout') { should match(/^MSPUB\.EXE\s+\*\\OFFICE1\*\s+(\S+\s?){2,14}$/) }
    its('stdout') { should match(/^OIS\.EXE\s+\*\\OFFICE1\*\s+(\S+\s?){2,14}$/) }
    its('stdout') { should match(/^OUTLOOK\.EXE\s+\*\\OFFICE1\*\s+(\S+\s?){2,14}$/) }
    its('stdout') { should match(/^POWERPNT\.EXE\s+\*\\OFFICE1\*\s+(\S+\s?){2,14}$/) }
    its('stdout') { should match(/^PPTVIEW\.EXE\s+\*\\OFFICE1\*\s+(\S+\s?){2,14}$/) }
    its('stdout') { should match(/^VISIO\.EXE\s+\*\\OFFICE1\*\s+(\S+\s?){2,14}$/) }
    its('stdout') { should match(/^VPREVIEW\.EXE\s+\*\\OFFICE1\*\s+(\S+\s?){2,14}$/) }
    its('stdout') { should match(/^WindowsLiveWriter\.exe\s+\*\\Windows Live\\Writer\s+(\S+\s?){2,14}$/) }
    its('stdout') { should match(/^WINWORD\.EXE\s+\*\\OFFICE1\*\s+(\S+\s?){2,14}$/) }
    its('stdout') { should match(/^wlmail\.exe\s+\*\\Windows Live\\Mail\s+(\S+\s?){2,14}$/) }
    its('stdout') { should match(/^wordpad\.exe\s+\*\\Windows NT\\Accessories\s+(\S+\s?){2,14}$/) }
  end
end

control 'windows-284' do
  title 'Ensure \'System ASLR\' is set to \'Enabled: Application Opt-In\''
  desc 'This setting determines how applications become enrolled in Address Space Layout Randomization (ASLR).

  The recommended state for this setting is: Enabled: Application Opt-In.'
  impact 1.0
  tag 'windows': %w[2012R2]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.9.24.6'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('Only for Windows Server 2012') do
    os[:name].include? '2012'
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\SysSettings') do
    it { should exist }
    it { should have_property 'ASLR' }
    its('AntiDetours') { should eq 3 }
  end
end

control 'windows-285' do
  title 'Ensure \'System DEP\' is set to \'Enabled: Application Opt-Out\''
  desc 'This setting determines how applications become enrolled in Data Execution Protection (DEP).

  The recommended state for this setting is: Enabled: Application Opt-Out.'
  impact 1.0
  tag 'windows': %w[2012R2]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.9.24.7'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('Only for Windows Server 2012') do
    os[:name].include? '2012'
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\SysSettings') do
    it { should exist }
    it { should have_property 'DEP' }
    its('DEP') { should cmp eq 2 }
  end
end

control 'windows-286' do
  title 'Ensure \'System SEHOP\' is set to \'Enabled: Application Opt-Out\''
  desc 'This setting determines how applications become enrolled in Structured Exception Handler Overwrite Protection (SEHOP).

  The recommended state for this setting is: Enabled: Application Opt-Out.'
  impact 1.0
  tag 'windows': %w[2012R2]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.9.24.8'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('Only for Windows Server 2012') do
    os[:name].include? '2012'
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\SysSettings') do
    it { should exist }
    it { should have_property 'SEHOP' }
    its('SEHOP') { should eq 2 }
  end
end

control 'windows-289' do
  title 'Ensure \'Application: Control Event Log behavior when the log file reaches its maximum size\' is set to \'Disabled\''
  desc 'This policy setting controls Event Log behavior when the log file reaches its maximum size.

  The recommended state for this setting is: Disabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.9.26.1.1'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.9.26.1.1'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\EventLog\\Application') do
    it { should exist }
    it { should have_property 'Retention' }
    its('Retention') { should eq 0 }
  end
end

control 'windows-290' do
  title 'Ensure \'Application: Specify the maximum log file size (KB)\' is set to \'Enabled: 32,768 or greater\''
  desc 'This policy setting specifies the maximum size of the log file in kilobytes. The maximum log file size can be configured between 1 megabyte (1,024 kilobytes) and 2 terabytes (2,147,483,647 kilobytes) in kilobyte increments.

  The recommended state for this setting is: Enabled: 32,768 or greater.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.9.26.1.2'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.9.26.1.2'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\EventLog\\Application') do
    it { should exist }
    it { should have_property 'MaxSize' }
    its('MaxSize') { should be >= 32768 }
  end
end

control 'windows-291' do
  title 'Ensure \'Security: Control Event Log behavior when the log file reaches its maximum size\' is set to \'Disabled\''
  desc 'This policy setting controls Event Log behavior when the log file reaches its maximum size.

  The recommended state for this setting is: Disabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.9.26.2.1'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.9.26.2.1'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\EventLog\\Security') do
    it { should exist }
    it { should have_property 'Retention' }
    its('Retention') { should eq 0 }
  end
end

control 'windows-292' do
  title 'Ensure \'Security: Specify the maximum log file size (KB)\' is set to \'Enabled: 196,608 or greater\''
  desc 'This policy setting specifies the maximum size of the log file in kilobytes. The maximum log file size can be configured between 1 megabyte (1,024 kilobytes) and 2 terabytes (2,147,483,647 kilobytes) in kilobyte increments.

  The recommended state for this setting is: Enabled: 196,608 or greater.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.9.26.2.2'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.9.26.2.2'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\EventLog\\Security') do
    it { should exist }
    it { should have_property 'MaxSize' }
    its('MaxSize') { should be >= 196608 }
  end
end

control 'windows-293' do
  title 'Ensure \'Setup: Control Event Log behavior when the log file reaches its maximum size\' is set to \'Disabled\''
  desc 'This policy setting controls Event Log behavior when the log file reaches its maximum size.

  The recommended state for this setting is: Disabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.9.26.3.1'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.9.26.3.1'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\EventLog\\Setup') do
    it { should exist }
    it { should have_property 'Retention' }
    its('Retention') { should eq 0 }
  end
end

control 'windows-294' do
  title 'Ensure \'Setup: Specify the maximum log file size (KB)\' is set to \'Enabled: 32,768 or greater\''
  desc 'This policy setting specifies the maximum size of the log file in kilobytes. The maximum log file size can be configured between 1 megabyte (1,024 kilobytes) and 2 terabytes (2,147,483,647 kilobytes) in kilobyte increments.

  The recommended state for this setting is: Enabled: 32,768 or greater.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.9.26.3.2'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.9.26.3.2'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\EventLog\\Setup') do
    it { should exist }
    it { should have_property 'MaxSize' }
    its('MaxSize') { should be >= 32768 }
  end
end

control 'windows-295' do
  title 'Ensure \'System: Control Event Log behavior when the log file reaches its maximum size\' is set to \'Disabled\''
  desc 'This policy setting controls Event Log behavior when the log file reaches its maximum size.

  The recommended state for this setting is: Disabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.9.26.4.1'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.9.26.4.1'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\EventLog\\System') do
    it { should exist }
    it { should have_property 'Retention' }
    its('Retention') { should eq 0 }
  end
end

control 'windows-296' do
  title 'Ensure \'System: Specify the maximum log file size (KB)\' is set to \'Enabled: 32,768 or greater\''
  desc 'Diese Richtlinieneinstellung gibt die maximale Größe der Protokolldatei in Kilobyte an. Die maximale Protokolldateigröße kann zwischen 1 Megabyte (1.024 Kilobyte) und 2 Terabyte (2.147.483.647 Kilobyte) in Kilobyte-Schritten konfiguriert werden.

  Der empfohlene Status für diese Einstellung ist: Enabled: 32,768 or greater.
  Es wird hier 262,144 kB empfohlen'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.9.26.4.4'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.9.26.4.2'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration'] # FIXME: check Baustein
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\EventLog\\System') do
    it { should exist }
    it { should have_property 'MaxSize' }
    its('MaxSize') { should be >= 32768 }
  end
end

control 'windows-297' do
  title 'Ensure \'Turn off Data Execution Prevention for Explorer\' is set to \'Disabled\''
  desc 'Disabling data execution prevention can allow certain legacy plug-in applications to function without terminating Explorer.

  The recommended state for this setting is: Disabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.9.30.2'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.9.30.2'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Explorer') do
    it { should exist }
    it { should have_property 'NoDataExecutionPrevention' }
    its('NoDataExecutionPrevention') { should eq 0 }
  end
end

control 'windows-298' do
  title 'Ensure \'Turn off heap termination on corruption\' is set to \'Disabled\''
  desc 'Without heap termination on corruption, legacy plug-in applications may continue to function when a File Explorer session has become corrupt. Ensuring that heap termination on corruption is active will prevent this.

  The recommended state for this setting is: Disabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.9.30.3'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.9.30.3'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Explorer') do
    it { should exist }
    it { should have_property 'NoHeapTerminationOnCorruption' }
    its('NoHeapTerminationOnCorruption') { should eq 0 }
  end
end

control 'windows-299' do
  title 'Ensure \'Turn off shell protocol protected mode\' is set to \'Disabled\''
  desc 'This policy setting allows you to configure the amount of functionality that the shell protocol can have. When using the full functionality of this protocol applications can open folders and launch files. The protected mode reduces the functionality of this protocol allowing applications to only open a limited set of folders. Applications are not able to open files with this protocol when it is in the protected mode. It is recommended to leave this protocol in the protected mode to increase the security of Windows.

  The recommended state for this setting is: Disabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.9.30.4'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.9.30.4'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer') do
    it { should exist }
    it { should have_property 'PreXPSP2ShellProtocolBehavior' }
    its('PreXPSP2ShellProtocolBehavior') { should eq 0 }
  end
end

control 'windows-300' do
  title 'Ensure \'Turn off Windows Location Provider\' is set to \'Enabled\''
  desc 'This policy setting turns off the Windows Location Provider feature for the computer.

  The recommended state for this setting is: Enabled.'
  impact 0.5
  tag 'windows': %w[2012R2]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.9.39.1.1'
  tag 'level': '2'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('Only for Windows Server 2012 and if attribute(\'level_1_or_2\') is set to 2') do
    ((os[:name].include? '2012') && attribute('level_1_or_2') == 2)
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\LocationAndSensors') do
    it { should exist }
    it { should have_property 'DisableWindowsLocationProvider' }
    its('DisableWindowsLocationProvider') { should eq 1 }
  end
end

control 'windows-301' do
  title 'Ensure \'Turn off location\' is set to \'Enabled\''
  desc 'This policy setting turns off the location feature for the computer.

  The recommended state for this setting is: Enabled.'
  impact 0.5
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.9.39.1.1'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.9.39.2'
  tag 'level': '2'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('This Control only executes if attribute(\'level_1_or_2\') is set to 2') do
    attribute('level_1_or_2') == 2
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\LocationAndSensors') do
    it { should exist }
    it { should have_property 'DisableLocation' }
    its('DisableLocation') { should eq 1 }
  end
end

control 'windows-302' do
  title 'Ensure \'Allow Message Service Cloud Sync\' is set to \'Disabled\''
  desc 'This policy setting allows backup and restore of cellular text messages to Microsoft\'s cloud services.

  The recommended state for this setting is: Disabled.'
  impact 0.5
  tag 'windows': %w[2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.9.43.1'
  tag 'level': '2'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('Only for Windows Server 2016, 2019 and if attribute(\'level_1_or_2\') is set to 2') do
    (((os[:name].include? '2016') || (os[:name].include? '2019')) && attribute('level_1_or_2') == 2)
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Messaging') do
    it { should exist }
    it { should have_property 'AllowMessageSync' }
    its('AllowMessageSync') { should eq 0 }
  end
end

control 'windows-303' do
  title 'Ensure \'Block all consumer Microsoft account user authentication\' is set to \'Enabled\''
  desc 'This setting determines whether applications and services on the device can utilize new consumer Microsoft account authentication via the Windows OnlineID and WebAccountManager APIs.

  The recommended state for this setting is: Enabled.'
  impact 1.0
  tag 'windows': %w[2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.9.44.1'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('Only for Windows Server 2016, 2019') do
    ((os[:name].include? '2016') || (os[:name].include? '2019'))
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\MicrosoftAccount') do
    it { should exist }
    it { should have_property 'DisableUserAuth' }
    its('DisableUserAuth') { should eq 1 }
  end
end

control 'windows-304' do
  title 'Ensure \'Prevent the usage of OneDrive for file storage\' is set to \'Enabled\''
  desc 'This policy setting lets you prevent apps and features from working with files on OneDrive using the Next Generation Sync Client.

  The recommended state for this setting is: Enabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.9.52.1'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.9.52.1'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\OneDrive') do
    it { should exist }
    it { should have_property 'DisableFileSyncNGSC' }
    its('DisableFileSyncNGSC') { should eq 1 }
  end
end

control 'windows-305' do
  title 'Ensure \'Prevent the usage of OneDrive for file storage on Windows 8.1\' is set to \'Enabled\''
  desc 'This policy setting lets you prevent apps and features from working with files on OneDrive using the legacy OneDrive/SkyDrive client.

  The recommended state for this setting is: Enabled.'
  impact 1.0
  tag 'windows': %w[2012R2]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.9.52.2'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('Only for Windows Server 2012') do
    os[:name].include? '2012'
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\OneDrive') do
    it { should exist }
    it { should have_property 'DisableFileSyncNGSC' }
    its('DisableFileSyncNGSC') { should eq 1 }
  end
end

control 'windows-306' do
  title 'Ensure \'Do not allow passwords to be saved\' is set to \'Enabled\''
  desc 'This policy setting helps prevent Remote Desktop Services / Terminal Services clients from saving passwords on a computer.

  The recommended state for this setting is: Enabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.9.58.2.2'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.9.58.2.2'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration', 'SYS.1.2.2.M6', 'Sichere Authentisierung und Autorisierung']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services') do
    it { should exist }
    it { should have_property 'DisablePasswordSaving' }
    its('DisablePasswordSaving') { should eq 1 }
  end
end

control 'windows-307' do
  title 'Ensure \'Restrict Remote Desktop Services users to a single Remote Desktop Services session\' is set to \'Enabled\''
  desc 'This policy setting allows you to restrict users to a single Remote Desktop Services session.

  The recommended state for this setting is: Enabled.'
  impact 0.5
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.9.58.3.2.1'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.9.58.3.2.1'
  tag 'level': '2'
  tag 'bsi': ['SYS.1.2.2.M3', 'Sichere Administration', 'SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('This Control only executes if attribute(\'level_1_or_2\') is set to 2') do
    attribute('level_1_or_2') == 2
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows NT\\Terminal Services') do
    it { should exist }
    it { should have_property 'fSingleSessionPerUser' }
    its('fSingleSessionPerUser') { should eq 1 }
  end
end

control 'windows-308' do
  title 'Ensure \'Do not allow COM port redirection\' is set to \'Enabled\''
  desc 'This policy setting specifies whether to prevent the redirection of data to client COM ports from the remote computer in a Remote Desktop Services session.

  The recommended state for this setting is: Enabled.'
  impact 0.5
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.9.58.3.3.1'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.9.58.3.3.1'
  tag 'level': '2'
  tag 'bsi': ['SYS.1.2.2.M3', 'Sichere Administration', 'SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('This Control only executes if attribute(\'level_1_or_2\') is set to 2') do
    attribute('level_1_or_2') == 2
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services') do
    it { should exist }
    it { should have_property 'fDisableCcm' }
    its('fDisableCcm') { should eq 1 }
  end
end

control 'windows-309' do
  title 'Ensure \'Do not allow drive redirection\' is set to \'Enabled\''
  desc ' This policy setting prevents users from sharing the local drives on their client computers to Terminal Servers that they access. Mapped drives appear in the session folder tree in Windows Explorer in the following format:

  \\\\TSClient\\
  <driveletter>$

  If local drives are shared they are left vulnerable to intruders who want to exploit the data that is stored on them.

  The recommended state for this setting is: Enabled.</driveletter>'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.9.58.3.3.2'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.9.58.3.3.2'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M3', 'Sichere Administration', 'SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services') do
    it { should exist }
    it { should have_property 'fDisableCdm' }
    its('fDisableCdm') { should eq 1 }
  end
end

control 'windows-310' do
  title 'Ensure \'Do not allow LPT port redirection\' is set to \'Enabled\''
  desc 'This policy setting specifies whether to prevent the redirection of data to client LPT ports during a Remote Desktop Services session.

  The recommended state for this setting is: Enabled.'
  impact 0.5
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.9.58.3.3.3'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.9.58.3.3.3'
  tag 'level': '2'
  tag 'bsi': ['SYS.1.2.2.M3', 'Sichere Administration', 'SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('This Control only executes if attribute(\'level_1_or_2\') is set to 2') do
    attribute('level_1_or_2') == 2
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services') do
    it { should exist }
    it { should have_property 'fDisableLPT' }
    its('fDisableLPT') { should eq 1 }
  end
end

control 'windows-311' do
  title 'Ensure \'Do not allow supported Plug and Play device redirection\' is set to \'Enabled\''
  desc 'This policy setting allows you to control the redirection of supported Plug and Play devices, such as Windows Portable Devices, to the remote computer in a Remote Desktop Services session.

  The recommended state for this setting is: Enabled.'
  impact 0.5
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.9.58.3.3.4'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.9.58.3.3.4'
  tag 'level': '2'
  tag 'bsi': ['SYS.1.2.2.M3', 'Sichere Administration', 'SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('This Control only executes if attribute(\'level_1_or_2\') is set to 2') do
    attribute('level_1_or_2') == 2
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services') do
    it { should exist }
    it { should have_property 'fDisablePNPRedir' }
    its('fDisablePNPRedir') { should eq 1 }
  end
end

control 'windows-312' do
  title 'Ensure \'Always prompt for password upon connection\' is set to \'Enabled\''
  desc 'This policy setting specifies whether Terminal Services always prompts the client computer for a password upon connection. You can use this policy setting to enforce a password prompt for users who log on to Terminal Services, even if they already provided the password in the Remote Desktop Connection client.

  The recommended state for this setting is: Enabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.9.58.3.9.1'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.9.58.3.9.1'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration', 'SYS.1.2.2.M6', 'Sichere Authentisierung und Autorisierung']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services') do
    it { should exist }
    it { should have_property 'fPromptForPassword' }
    its('fPromptForPassword') { should eq 1 }
  end
end

control 'windows-313' do
  title 'Ensure \'Require secure RPC communication\' is set to \'Enabled\''
  desc 'This policy setting allows you to specify whether a terminal server requires secure remote procedure call (RPC) communication with all clients or allows unsecured communication.

  You can use this policy setting to strengthen the security of RPC communication with clients by allowing only authenticated and encrypted requests.

  The recommended state for this setting is: Enabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.9.58.3.9.2'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.9.58.3.9.2'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows NT\\Terminal Services') do
    it { should exist }
    it { should have_property 'fEncryptRPCTraffic' }
    its('fEncryptRPCTraffic') { should eq 1 }
  end
end

control 'windows-314' do
  title 'Ensure \'Set client connection encryption level\' is set to \'Enabled: High Level\''
  desc 'This policy setting specifies whether to require the use of a specific encryption level to secure communications between client computers and RD Session Host servers during Remote Desktop Protocol (RDP) connections. This policy only applies when you are using native RDP encryption. However, native RDP encryption (as opposed to SSL encryption) is not recommended. This policy does not apply to SSL encryption.

  The recommended state for this setting is: Enabled: High Level.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.9.58.3.9.3'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.9.58.3.9.3'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration', 'SYS.1.2.2.M6', 'Sichere Authentisierung und Autorisierung']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services') do
    it { should exist }
    it { should have_property 'MinEncryptionLevel' }
    its('MinEncryptionLevel') { should eq 3 }
  end
end

control 'windows-315' do
  title 'Ensure \'Set time limit for active but idle Remote Desktop Services sessions\' is set to \'Enabled: 15 minutes or less\''
  desc 'This policy setting allows you to specify the maximum amount of time that an active Remote Desktop Services session can be idle (without user input) before it is automatically disconnected.

  The recommended state for this setting is: Enabled: 15 minutes or less.'
  impact 0.5
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.9.58.3.10.1'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.9.58.3.10.1'
  tag 'level': '2'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('This Control only executes if attribute(\'level_1_or_2\') is set to 2') do
    attribute('level_1_or_2') == 2
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services') do
    it { should exist }
    it { should have_property 'MaxIdleTime' }
    its('MaxIdleTime') { should be <= 900000 }
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services') do
    it { should exist }
    it { should have_property 'MaxIdleTime' }
    its('MaxIdleTime') { should_not eq 0 }
  end
end

control 'windows-316' do
  title 'Ensure \'Set time limit for disconnected sessions\' is set to \'Enabled: 1 minute\''
  desc 'This policy setting allows you to configure a time limit for disconnected Remote Desktop Services sessions.

  The recommended state for this setting is: Enabled: 1 minute.'
  impact 0.5
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.9.58.3.10.2'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.9.58.3.10.2'
  tag 'level': '2'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('This Control only executes if attribute(\'level_1_or_2\') is set to 2') do
    attribute('level_1_or_2') == 2
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services') do
    it { should exist }
    it { should have_property 'MaxDisconnectionTime' }
    its('MaxDisconnectionTime') { should eq 60000 }
  end
end

control 'windows-317' do
  title 'Ensure \'Do not delete temp folders upon exit\' is set to \'Disabled\''
  desc 'This policy setting specifies whether Remote Desktop Services retains a user\'s per-session temporary folders at logoff.

  The recommended state for this setting is: Disabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.9.58.3.11.1'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.9.58.3.11.1'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services') do
    it { should exist }
    it { should have_property 'DeleteTempDirsOnExit' }
    its('DeleteTempDirsOnExit') { should eq 1 }
  end
end

control 'windows-318' do
  title 'Ensure \'Do not use temporary folders per session\' is set to \'Disabled\''
  desc 'By default, Remote Desktop Services creates a separate temporary folder on the RD Session Host server for each active session that a user maintains on the RD Session Host server. The temporary folder is created on the RD Session Host server in a Temp folder under the user\'s profile folder and is named with the \'sessionid.\' This temporary folder is used to store individual temporary files.

  To reclaim disk space, the temporary folder is deleted when the user logs off from a session.

  The recommended state for this setting is: Disabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.9.58.3.11.2'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.9.58.3.11.2'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows NT\\Terminal Services') do
    it { should exist }
    it { should have_property 'PerSessionTempDir' }
    its('PerSessionTempDir') { should eq 1 }
  end
end

control 'windows-319' do
  title 'Ensure \'Prevent downloading of enclosures\' is set to \'Enabled\''
  desc 'This policy setting prevents the user from having enclosures (file attachments) downloaded from a feed to the user\'s computer.

  The recommended state for this setting is: Enabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.9.59.1'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.9.59.1'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Internet Explorer\\Feeds') do
    it { should exist }
    it { should have_property 'DisableEnclosureDownload' }
    its('DisableEnclosureDownload') { should eq 1 }
  end
end

control 'windows-320' do
  title 'Ensure \'Allow Cloud Search\' is set to \'Enabled: Disable Cloud Search\''
  desc 'This policy setting allows search and Cortana to search cloud sources like OneDrive and SharePoint.

  The recommended state for this setting is: Enabled: Disable Cloud Search.'
  impact 0.5
  tag 'windows': %w[2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.9.60.2'
  tag 'level': '2'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('Only for Windows Server 2016, 2019 and if attribute(\'level_1_or_2\') is set to 2') do
    (((os[:name].include? '2016') || (os[:name].include? '2019')) && attribute('level_1_or_2') == 2)
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Search') do
    it { should exist }
    it { should have_property 'AllowCloudSearch' }
    its('AllowCloudSearch') { should eq 0 }
  end
end

control 'windows-321' do
  title 'Ensure \'Allow indexing of encrypted files\' is set to \'Disabled\''
  desc 'This policy setting controls whether encrypted items are allowed to be indexed. When this setting is changed, the index is rebuilt completely. Full volume encryption (such as BitLocker Drive Encryption or a non-Microsoft solution) must be used for the location of the index to maintain security for encrypted files.

  The recommended state for this setting is: Disabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.9.60.2'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.9.60.3'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Search') do
    it { should exist }
    it { should have_property 'AllowIndexingEncryptedStoresOrItems' }
    its('AllowIndexingEncryptedStoresOrItems') { should eq 0 }
  end
end

control 'windows-322' do
  title 'Ensure \'Set what information is shared in Search\' is set to \'Enabled: Anonymous info\''
  desc 'Various levels of information can be shared with Bing in Search, to include user information and location. Configuring this setting prevents users from selecting the level of information shared and enables the most restrictive selection.

  The recommended state for this setting is: Enabled: Anonymous info.'
  impact 0.5
  tag 'windows': %w[2012R2]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.9.60.3'
  tag 'level': '2'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('Only for Windows Server 2012 and if attribute(\'level_1_or_2\') is set to 2') do
    ((os[:name].include? '2012') && attribute('level_1_or_2') == 2)
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Search') do
    it { should exist }
    it { should have_property 'ConnectedSearchPrivacy' }
    its('ConnectedSearchPrivacy') { should eq 3 }
  end
end

control 'windows-323' do
  title 'Ensure \'Turn off KMS Client Online AVS Validation\' is set to \'Enabled\''
  desc 'The Key Management Service (KMS) is a Microsoft license activation method that entails setting up a local server that stores the licenses. The server itself needs to connect to Microsoft to activate the KMS service, but subsequent on-network clients can activate Microsoft Windows OS and/or their Microsoft Office via the KMS server instead of connecting directly to Microsoft. This policy setting lets you opt-out of sending KMS client activation data to Microsoft automatically.

  The recommended state for this setting is: Enabled.'
  impact 0.5
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.9.65.1'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.9.65.1'
  tag 'level': '2'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('This Control only executes if attribute(\'level_1_or_2\') is set to 2') do
    attribute('level_1_or_2') == 2
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\CurrentVersion\\Software Protection Platform') do
    it { should exist }
    it { should have_property 'NoGenTicket' }
    its('NoGenTicket') { should eq 1 }
  end
end

control 'windows-324' do
  title 'Ensure \'Configure local setting override for reporting to Microsoft MAPS\' is set to \'Disabled\''
  desc 'This policy setting configures a local override for the configuration to join Microsoft Active Protection Service (MAPS), which Microsoft has now renamed to \'Windows Defender Antivirus Cloud Protection Service\'. This setting can only be set by Group Policy.

  The recommended state for this setting is: Disabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.9.76.3.1'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.9.76.3.1'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Spynet') do
    it { should exist }
    it { should have_property 'LocalSettingOverrideSpynetReporting' }
    its('LocalSettingOverrideSpynetReporting') { should eq 0 }
  end
end

control 'windows-325' do
  title 'Ensure \'Join Microsoft MAPS\' is set to \'Disabled\''
  desc 'This policy setting allows you to join Microsoft MAPS. Microsoft MAPS is the online community that helps you choose how to respond to potential threats. The community also helps stop the spread of new malicious software infections. You can choose to send basic or additional information about detected software. Additional information helps Microsoft create new definitions and help it to protect your computer.

  Possible options are: (0x0) Disabled (default) (0x1) Basic membership (0x2) Advanced membership

  Basic membership will send basic information to Microsoft about software that has been detected including where the software came from the actions that you apply or that are applied automatically and whether the actions were successful.

  Advanced membership in addition to basic information will send more information to Microsoft about malicious software spyware and potentially unwanted software including the location of the software file names how the software operates and how it has impacted your computer.

  The recommended state for this setting is: Disabled.'
  impact 0.5
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.9.76.3.2'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.9.76.3.2'
  tag 'level': '2'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('This Control only executes if attribute(\'level_1_or_2\') is set to 2') do
    attribute('level_1_or_2') == 2
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Spynet') do
    it { should exist }
    it { should have_property 'SpynetReporting' }
    its('SpynetReporting') { should eq 0 }
  end
end

control 'windows-326' do
  title 'Ensure \'Turn on behavior monitoring\' is set to \'Enabled\''
  desc 'This policy setting allows you to configure behavior monitoring for Windows Defender Antivirus.

  The recommended state for this setting is: Enabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.9.76.7.1'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.9.76.7.1'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection') do
    it { should exist }
    it { should have_property 'DisableBehaviorMonitoring' }
    its('DisableBehaviorMonitoring') { should eq 0 }
  end
end

control 'windows-327' do
  title 'Ensure \'Configure Watson events\' is set to \'Disabled\''
  desc 'This policy setting allows you to configure whether or not Watson events are sent.

  The recommended state for this setting is: Disabled.'
  impact 0.5
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.9.76.9.1'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.9.76.9.1'
  tag 'level': '2'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('This Control only executes if attribute(\'level_1_or_2\') is set to 2') do
    attribute('level_1_or_2') == 2
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Reporting') do
    it { should exist }
    it { should have_property 'DisableGenericRePorts' }
    its('DisableGenericRePorts') { should eq 1 }
  end
end

control 'windows-328' do
  title 'Ensure \'Scan removable drives\' is set to \'Enabled\''
  desc 'This policy setting allows you to manage whether or not to scan for malicious software and unwanted software in the contents of removable drives, such as USB flash drives, when running a full scan.

  The recommended state for this setting is: Enabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.9.76.10.1'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.9.76.10.1'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Scan') do
    it { should exist }
    it { should have_property 'DisableRemovableDriveScanning' }
    its('DisableRemovableDriveScanning') { should eq 0 }
  end
end

control 'windows-329' do
  title 'Ensure \'Turn on e-mail scanning\' is set to \'Enabled\''
  desc 'This policy setting allows you to configure e-mail scanning. When e-mail scanning is enabled, the engine will parse the mailbox and mail files, according to their specific format, in order to analyze the mail bodies and attachments. Several e-mail formats are currently supported, for example: pst (Outlook), dbx, mbx, mime (Outlook Express), binhex (Mac).

  The recommended state for this setting is: Enabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.9.76.10.2'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.9.76.10.2'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Scan') do
    it { should exist }
    it { should have_property 'DisableEmailScanning' }
    its('DisableEmailScanning') { should eq 0 }
  end
end

control 'windows-330' do
  title 'Ensure \'Configure Attack Surface Reduction rules\' is set to \'Enabled\''
  desc 'This policy setting controls the state for the Attack Surface Reduction (ASR) rules.

  The recommended state for this setting is: Enabled.'
  impact 1.0
  tag 'windows': %w[2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.9.76.13.1.1'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('Only for Windows Server 2016, 2019') do
    ((os[:name].include? '2016') || (os[:name].include? '2019'))
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Windows Defender Exploit Guard\\ASR') do
    it { should exist }
    it { should have_property 'ExploitGuard_ASR_Rules' }
    its('ExploitGuard_ASR_Rules') { should eq 1 }
  end
end

control 'windows-331' do
  title 'Ensure \'Configure Attack Surface Reduction rules: Set the state for each ASR rule\' is \'configured\''
  desc 'The recommended state for this setting is:

  75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84 - 1 (Block Office applications from injecting code into other processes)
  3b576869-a4ec-4529-8536-b80a7769e899 - 1 (Block Office applications from creating executable content)
  d4f940ab-401b-4efc-aadc-ad5f3c50688a - 1 (Block Office applications from creating child processes)
  92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b - 1 (Block Win32 API calls from Office macro)
  5beb7efe-fd9a-4556-801d-275e5ffc04cc - 1 (Block execution of potentially obfuscated scripts)
  d3e037e1-3eb8-44c8-a917-57927947596d - 1 (Block JavaScript or VBScript from launching downloaded executable content)
  be9ba2d9-53ea-4cdc-84e5-9b1eeee46550 - 1 (Block executable content from email client and webmail)

  Note: More information on ASR rules can be found at the following link: [Use Attack surface reduction rules to prevent malware infection | Microsoft Docs](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-exploit-guard/attack-surface-reduction-exploit-guard)'
  impact 1.0
  tag 'windows': %w[2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.9.76.13.1.2'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('Only for Windows Server 2016, 2019') do
    ((os[:name].include? '2016') || (os[:name].include? '2019'))
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Windows Defender Exploit Guard\\ASR\\Rules') do
    it { should exist }
    it { should have_property '75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84' }
    its('75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84') { should eq 1 }
    it { should have_property '3b576869-a4ec-4529-8536-b80a7769e899' }
    its('3b576869-a4ec-4529-8536-b80a7769e899') { should eq 1 }
    it { should have_property 'd4f940ab-401b-4efc-aadc-ad5f3c50688a' }
    its('d4f940ab-401b-4efc-aadc-ad5f3c50688a') { should eq 1 }
    it { should have_property '92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b' }
    its('92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b') { should eq 1 }
    it { should have_property '5beb7efe-fd9a-4556-801d-275e5ffc04cc' }
    its('5beb7efe-fd9a-4556-801d-275e5ffc04cc') { should eq 1 }
    it { should have_property 'd3e037e1-3eb8-44c8-a917-57927947596d' }
    its('d3e037e1-3eb8-44c8-a917-57927947596d') { should eq 1 }
    it { should have_property 'be9ba2d9-53ea-4cdc-84e5-9b1eeee46550' }
    its('be9ba2d9-53ea-4cdc-84e5-9b1eeee46550') { should eq 1 }
  end
end

control 'windows-332' do
  title 'Ensure \'Prevent users and apps from accessing dangerous websites\' is set to \'Enabled: Block\''
  desc 'This policy setting controls Windows Defender Exploit Guard network protection.

  The recommended state for this setting is: Enabled: Block.'
  impact 1.0
  tag 'windows': %w[2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.9.76.13.3.1'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('Only for Windows Server 2016, 2019') do
    ((os[:name].include? '2016') || (os[:name].include? '2019'))
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Windows Defender Exploit Guard\\Network Protection') do
    it { should exist }
    it { should have_property 'EnableNetworkProtection' }
    its('EnableNetworkProtection') { should eq 1 }
  end
end

control 'windows-333' do
  title 'Ensure \'Turn off Windows Defender AntiVirus\' is set to \'Disabled\''
  desc 'This policy setting turns off Windows Defender Antivirus. If the setting is configured to Disabled, Windows Defender Antivirus runs and computers are scanned for malware and other potentially unwanted software.

  The recommended state for this setting is: Disabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.9.76.10.2'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.9.76.14'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender') do
    it { should exist }
    it { should have_property 'DisableAntiSpyware' }
    its('DisableAntiSpyware') { should eq 0 }
  end
end

control 'windows-334' do
  title 'Ensure \'Prevent users from modifying settings\' is set to \'Enabled\''
  desc 'This policy setting prevent users from making changes to the Exploit protection settings area in the Windows Defender Security Center.

  The recommended state for this setting is: Enabled.'
  impact 1.0
  tag 'windows': %w[2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.9.79.1'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('Only for Windows Server 2016, 2019') do
    ((os[:name].include? '2016') || (os[:name].include? '2019'))
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender Security Center\\App and Browser protection') do
    it { should exist }
    it { should have_property 'DisallowExploitProtectionOverride' }
    its('DisallowExploitProtectionOverride') { should eq 1 }
  end
end

control 'windows-335' do
  title 'Ensure \'Configure Windows SmartScreen\' is set to \'Enabled\''
  desc 'This policy setting allows you to manage the behavior of Windows SmartScreen. Windows SmartScreen helps keep PCs safer by warning users before running unrecognized programs downloaded from the Internet. Some information is sent to Microsoft about files and programs run on PCs with this feature enabled.

  The recommended state for this setting is: Enabled.'
  impact 1.0
  tag 'windows': %w[2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.9.80.1.1'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.9.80.1.1'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\System') do
    it { should exist }
    it { should have_property 'EnableSmartScreen' }
    its('EnableSmartScreen') { should eq 1 }
  end
end

control 'windows-336' do
  title 'Ensure \'Configure Default consent\' is set to \'Enabled: Always ask before sending data\''
  desc 'This setting allows you to set the default consent handling for error reports.

  The recommended state for this setting is: Enabled: Always ask before sending data.'
  impact 1.0
  tag 'windows': %w[2012R2]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.9.81.2.1'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('Only for Windows Server 2012') do
    os[:name].include? '2012'
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Error Reporting\\Consent') do
    it { should exist }
    it { should have_property 'DefaultConsent' }
    its('DefaultConsent') { should eq 1 }
  end
end

control 'windows-337' do
  title 'Ensure \'Automatically send memory dumps for OS-generated error reports\' is set to \'Disabled\''
  desc 'This policy setting controls whether memory dumps in support of OS-generated error reports can be sent to Microsoft automatically. This policy does not apply to error reports generated by 3rd-party products, or additional data other than memory dumps.

  The recommended state for this setting is: Disabled.'
  impact 1.0
  tag 'windows': %w[2012R2]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.9.81.3'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('Only for Windows Server 2012') do
    os[:name].include? '2012'
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Error Reporting') do
    it { should exist }
    it { should have_property 'AutoApproveOSDumps' }
    its('AutoApproveOSDumps') { should eq 0 }
  end
end

control 'windows-338' do
  title 'Ensure \'Allow suggested apps in Windows Ink Workspace\' is set to \'Disabled\''
  desc 'This policy setting determines whether suggested apps in Windows Ink Workspace are allowed.

  The recommended state for this setting is: Disabled.'
  impact 0.5
  tag 'windows': %w[2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.9.84.1'
  tag 'level': '2'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('Only for Windows Server 2016, 2019 and if attribute(\'level_1_or_2\') is set to 2') do
    (((os[:name].include? '2016') || (os[:name].include? '2019')) && attribute('level_1_or_2') == 2)
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\WindowsInkWorkspace') do
    it { should exist }
    it { should have_property 'AllowSuggestedAppsInWindowsInkWorkspace' }
    its('AllowSuggestedAppsInWindowsInkWorkspace') { should eq 0 }
  end
end

control 'windows-339' do
  title 'Ensure \'Allow Windows Ink Workspace\' is set to \'Enabled: On, but disallow access above lock\' OR \'Disabled\' but not \'Enabled: On\''
  desc 'This policy setting determines whether Windows Ink items are allowed above the lock screen.

  The recommended state for this setting is: Enabled: On, but disallow access above lock OR Disabled.'
  impact 1.0
  tag 'windows': %w[2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.9.84.2'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('Only for Windows Server 2016, 2019') do
    ((os[:name].include? '2016') || (os[:name].include? '2019'))
  end
  describe.one do
    describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\WindowsInkWorkspace') do
      it { should exist }
      it { should have_property 'AllowWindowsInkWorkspace' }
      its('AllowWindowsInkWorkspace') { should eq 1 }
    end
    describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\WindowsInkWorkspace') do
      it { should exist }
      it { should have_property 'AllowWindowsInkWorkspace' }
      its('AllowWindowsInkWorkspace') { should eq 0 }
    end
  end
end

control 'windows-340' do
  title 'Ensure \'Allow user control over installs\' is set to \'Disabled\''
  desc 'Permits users to change installation options that typically are available only to system administrators. The security features of Windows Installer prevent users from changing installation options typically reserved for system administrators, such as specifying the directory to which files are installed. If Windows Installer detects that an installation package has permitted the user to change a protected option, it stops the installation and displays a message. These security features operate only when the installation program is running in a privileged security context in which it has access to directories denied to the user.

  The recommended state for this setting is: Disabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.9.85.1'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.9.85.1'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Installer') do
    it { should exist }
    it { should have_property 'EnableUserControl' }
    its('EnableUserControl') { should eq 0 }
  end
end

control 'windows-341' do
  title 'Ensure \'Always install with elevated privileges\' is set to \'Disabled\''
  desc 'This setting controls whether or not Windows Installer should use system permissions when it installs any program on the system.

  **Note:** This setting appears both in the Computer Configuration and User Configuration folders. To make this setting effective, you must enable the setting in both folders.

  **Caution:** If enabled, skilled users can take advantage of the permissions this setting grants to change their privileges and gain permanent access to restricted files and folders. Note that the User Configuration version of this setting is not guaranteed to be secure.

  The recommended state for this setting is: Disabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.9.85.2'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.9.85.2'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer') do
    it { should exist }
    it { should have_property 'AlwaysInstallElevated' }
    its('AlwaysInstallElevated') { should eq 0 }
  end
end

control 'windows-342' do
  title 'Ensure \'Prevent Internet Explorer security prompt for Windows Installer scripts\' is set to \'Disabled\''
  desc 'This policy setting controls whether Web-based programs are allowed to install software on the computer without notifying the user.

  The recommended state for this setting is: Disabled.'
  impact 0.5
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.9.85.3'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.9.85.3'
  tag 'level': '2'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('This Control only executes if attribute(\'level_1_or_2\') is set to 2') do
    attribute('level_1_or_2') == 2
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Installer') do
    it { should exist }
    it { should have_property 'SafeForScripting' }
    its('SafeForScripting') { should eq 0 }
  end
end

control 'windows-343' do
  title 'Ensure \'Sign-in last interactive user automatically after a system-initiated restart\' is set to \'Disabled\''
  desc 'This policy setting controls whether a device will automatically sign-in the last interactive user after Windows Update restarts the system.

  The recommended state for this setting is: Disabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.9.86.1'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.9.86.1'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\policies\\system') do
    it { should exist }
    it { should have_property 'DisableAutomaticRestartSignOn' }
    its('DisableAutomaticRestartSignOn') { should eq 1 }
  end
end

control 'windows-344' do
  title 'Ensure \'Turn on PowerShell Script Block Logging\' is set to \'Disabled\''
  desc 'This policy setting enables logging of all PowerShell script input to the Microsoft-Windows-PowerShell/Operational event log.

  The recommended state for this setting is: Disabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.9.95.1'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.9.95.1'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging') do
    it { should exist }
    it { should have_property 'EnableScriptBlockLogging' }
    its('EnableScriptBlockLogging') { should eq 0 }
  end
end

control 'windows-345' do
  title 'Ensure \'Turn on PowerShell Transcription\' is set to \'Disabled\''
  desc 'This Policy setting lets you capture the input and output of Windows PowerShell commands into text-based transcripts.

  The recommended state for this setting is: Disabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.9.95.2'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.9.95.2'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\Transcription') do
    it { should exist }
    it { should have_property 'EnableTranscripting' }
    its('EnableTranscripting') { should eq 0 }
  end
end

control 'windows-346' do
  title 'Ensure \'Allow Basic authentication\' is set to \'Disabled\''
  desc 'This policy setting allows you to manage whether the Windows Remote Management (WinRM) client uses Basic authentication.

  The recommended state for this setting is: Disabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.9.97.1.1'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.9.97.1.1'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M3', 'Sichere Administration', 'SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WinRM\\Client') do
    it { should exist }
    it { should have_property 'AllowBasic' }
    its('AllowBasic') { should eq 0 }
  end
end

control 'windows-347' do
  title 'Ensure \'Allow unencrypted traffic\' is set to \'Disabled\''
  desc 'This policy setting allows you to manage whether the Windows Remote Management (WinRM) client sends and receives unencrypted messages over the network.

  The recommended state for this setting is: Disabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.9.97.1.2'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.9.97.1.2'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M3', 'Sichere Administration', 'SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WinRM\\Client') do
    it { should exist }
    it { should have_property 'AllowUnencryptedTraffic' }
    its('AllowUnencryptedTraffic') { should eq 0 }
  end
end

control 'windows-348' do
  title 'Ensure \'Disallow Digest authentication\' is set to \'Enabled\''
  desc 'This policy setting allows you to manage whether the Windows Remote Management (WinRM) client will not use Digest authentication.

  The recommended state for this setting is: Enabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.9.97.1.3'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.9.97.1.3'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M3', 'Sichere Administration', 'SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WinRM\\Client') do
    it { should exist }
    it { should have_property 'AllowDigest' }
    its('AllowDigest') { should eq 0 }
  end
end

control 'windows-349' do
  title 'Ensure \'Allow Basic authentication\' is set to \'Disabled\''
  desc 'This policy setting allows you to manage whether the Windows Remote Management (WinRM) service accepts Basic authentication from a remote client.

  The recommended state for this setting is: Disabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.9.97.2.1'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.9.97.2.1'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M3', 'Sichere Administration', 'SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WinRM\\Service') do
    it { should exist }
    it { should have_property 'AllowBasic' }
    its('AllowBasic') { should eq 0 }
  end
end

control 'windows-350' do
  title 'Ensure \'Allow remote server management through WinRM\' is set to \'Disabled\''
  desc 'This policy setting allows you to manage whether the Windows Remote Management (WinRM) service automatically listens on the network for requests on the HTTP transport over the default HTTP port.

  The recommended state for this setting is: Disabled.'
  impact 0.5
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.9.97.2.2'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.9.97.2.2'
  tag 'level': '2'
  tag 'bsi': ['SYS.1.2.2.M3', 'Sichere Administration', 'SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('This Control only executes if attribute(\'level_1_or_2\') is set to 2') do
    attribute('level_1_or_2') == 2
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Service') do
    it { should exist }
    it { should have_property 'AllowAutoConfig' }
    its('AllowAutoConfig') { should eq 0 }
  end
end

control 'windows-351' do
  title 'Ensure \'Allow unencrypted traffic\' is set to \'Disabled\''
  desc 'This policy setting allows you to manage whether the Windows Remote Management (WinRM) service sends and receives unencrypted messages over the network.

  The recommended state for this setting is: Disabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.9.97.2.3'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.9.97.2.3'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M3', 'Sichere Administration', 'SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WinRM\\Service') do
    it { should exist }
    it { should have_property 'AllowUnencryptedTraffic' }
    its('AllowUnencryptedTraffic') { should eq 0 }
  end
end

control 'windows-352' do
  title 'Ensure \'Disallow WinRM from storing RunAs credentials\' is set to \'Enabled\''
  desc 'This policy setting allows you to manage whether the Windows Remote Management (WinRM) service will not allow RunAs credentials to be stored for any plug-ins.

  The recommended state for this setting is: Enabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.9.97.2.4'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.9.97.2.4'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M3', 'Sichere Administration', 'SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WinRM\\Service') do
    it { should exist }
    it { should have_property 'DisableRunAs' }
    its('DisableRunAs') { should eq 1 }
  end
end

control 'windows-353' do
  title 'Ensure \'Allow Remote Shell Access\' is set to \'Disabled\''
  desc 'This policy setting allows you to manage configuration of remote access to all supported shells to execute scripts and commands.

  The recommended state for this setting is: Disabled.'
  impact 0.5
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.9.98.1'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.9.98.1'
  tag 'level': '2'
  tag 'bsi': ['SYS.1.2.2.M3', 'Sichere Administration', 'SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('This Control only executes if attribute(\'level_1_or_2\') is set to 2') do
    attribute('level_1_or_2') == 2
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WinRM\\Service\\WinRS') do
    it { should exist }
    it { should have_property 'AllowRemoteShellAccess' }
    its('AllowRemoteShellAccess') { should eq 0 }
  end
end

control 'windows-354' do
  title 'Ensure \'Manage preview builds\' is set to \'Enabled: Disable preview builds\''
  desc 'This policy setting determines whether users can access the Windows Insider Program controls in Settings -> Update and Security. These controls enable users to make their devices available for downloading and installing preview (beta) builds of Windows software.

  The recommended state for this setting is: Enabled: Disable preview builds.'
  impact 1.0
  tag 'windows': %w[2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.9.101.1.1'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M3', 'Sichere Administration', 'SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('Only for Windows Server 2016, 2019') do
    ((os[:name].include? '2016') || (os[:name].include? '2019'))
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate') do
    it { should exist }
    it { should have_property 'ManagePreviewBuilds' }
    its('ManagePreviewBuilds') { should eq 1 }
    it { should have_property 'ManagePreviewBuildsPolicyValue' }
    its('ManagePreviewBuildsPolicyValue') { should eq 1 }
  end
end

control 'windows-355' do
  title 'Ensure \'Select when Feature Updates are received\' is set to \'Enabled: Current Branch for Business, 180 days\''
  desc 'This policy setting determines what type of feature updates to receive, and when.

  The branch readiness level for each new Windows 10 feature update is initially considered a \'Current Branch\' (CB) release, to be used by organizations for initial deployments. Once Microsoft has verified the feature update should be considered for enterprise deployment, it will be declared a branch readiness level of \'Current Branch for Business\' (CBB).

  The recommended state for this setting is: Enabled: Current Branch for Business, 180 days.'
  impact 1.0
  tag 'windows': %w[2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.9.101.1.2'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M3', 'Sichere Administration', 'SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('Only for Windows Server 2016, 2019') do
    ((os[:name].include? '2016') || (os[:name].include? '2019'))
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate') do
    it { should exist }
    it { should have_property 'DeferFeatureUpdates' }
    its('DeferFeatureUpdates') { should eq 1 }
    it { should have_property 'DeferFeatureUpdatesPeriodInDays' }
    its('DeferFeatureUpdatesPeriodInDays') { should eq 180 }
    it { should have_property 'BranchReadinessLevel' }
    its('BranchReadinessLevel') { should eq 32 }
  end
end

control 'windows-356' do
  title 'Ensure \'Select when Quality Updates are received\' is set to \'Enabled: 0 days\''
  desc 'This settings controls when Quality Updates are received.

  The recommended state for this setting is: Enabled: 0 days.'
  impact 1.0
  tag 'windows': %w[2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.9.101.1.3'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('Only for Windows Server 2016, 2019') do
    ((os[:name].include? '2016') || (os[:name].include? '2019'))
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate') do
    it { should exist }
    it { should have_property 'DeferQualityUpdates' }
    its('DeferQualityUpdates') { should eq 1 }
    it { should have_property 'DeferQualityUpdatesPeriodInDays' }
    its('DeferQualityUpdatesPeriodInDays') { should eq 0 }
  end
end

control 'windows-357' do
  title 'Ensure \'Configure Automatic Updates\' is set to \'Enabled\''
  desc 'This policy setting specifies whether computers in your environment will receive security updates from Windows Update or WSUS. If you configure this policy setting to Enabled, the operating system will recognize when a network connection is available and then use the network connection to search Windows Update or your designated intranet site for updates that apply to them.

  After you configure this policy setting to Enabled, select one of the following three options in the Configure Automatic Updates Properties dialog box to specify how the service will work:

  * 2 - Notify for download and auto install **(Notify before downloading any updates)**
  * 3 - Auto download and notify for install **(Download the updates automatically and notify when they are ready to be installed.) (Default setting)**
  * 4 - Auto download and schedule the install **(Automatically download updates and install them on the schedule specified below.))**
  * 5 - Allow local admin to choose setting **(Leave decision on above choices up to the local Administrators (Not Recommended))**
  The recommended state for this setting is: Enabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.9.101.2'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.9.101.2'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU') do
    it { should exist }
    it { should have_property 'NoAutoUpdate' }
    its('NoAutoUpdate') { should eq 0 }
  end
end

control 'windows-358' do
  title 'Ensure \'Configure Automatic Updates: Scheduled install day\' is set to \'0 - Every day\''
  desc 'This policy setting specifies when computers in your environment will receive security updates from Windows Update or WSUS.

  The recommended state for this setting is: 0 - Every day.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.9.101.3'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.9.101.3'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU') do
    it { should exist }
    it { should have_property 'ScheduledInstallDay' }
    its('ScheduledInstallDay') { should eq 0 }
  end
end

control 'windows-359' do
  title 'Ensure \'No auto-restart with logged on users for scheduled automatic updates installations\' is set to \'Disabled\''
  desc 'This policy setting specifies that Automatic Updates will wait for computers to be restarted by the users who are logged on to them to complete a scheduled installation.

  The recommended state for this setting is: Disabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.9.101.4'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.9.101.4'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU') do
    it { should exist }
    it { should have_property 'NoAutoRebootWithLoggedOnUsers' }
    its('NoAutoRebootWithLoggedOnUsers') { should eq 0 }
  end
end

control 'windows-360' do
  title 'Ensure \'Enable screen saver\' is set to \'Enabled\''
  desc 'This policy setting enables/disables the use of desktop screen savers.

  The recommended state for this setting is: Enabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '19.1.3.1'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '19.1.3.1'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M3', 'Sichere Administration', 'SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  registry_key(hive: 'HKEY_USERS').children(/^S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]{3,}$/).map { |x| x.to_s + '\\Software\\Policies\\Microsoft\\Windows\\Control Panel\\Desktop' }.each do |entry|
    describe registry_key(entry) do
      it { should exist }
      it { should have_property 'ScreenSaveActive' }
      its('ScreenSaveActive') { should eq 1 }
    end
  end
end

control 'windows-361' do
  title 'Ensure \'Force specific screen saver: Screen saver executable name\' is set to \'Enabled: scrnsave.scr\''
  desc 'This policy setting specifies the screen saver for the user\'s desktop.

  The recommended state for this setting is: Enabled: scrnsave.scr.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '19.1.3.2'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '19.1.3.2'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  registry_key(hive: 'HKEY_USERS').children(/^S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]{3,}$/).map { |x| x.to_s + '\\Software\\Policies\\Microsoft\\Windows\\Control Panel\\Desktop' }.each do |entry|
    describe registry_key(entry) do
      it { should exist }
      it { should have_property 'SCRNSAVE.EXE' }
      its(['SCRNSAVE.EXE']) { should eq 'scrnsave.scr' }
    end
  end
end

control 'windows-362' do
  title 'Ensure \'Password protect the screen saver\' is set to \'Enabled\''
  desc 'This setting determines whether screen savers used on the computer are password protected.

  The recommended state for this setting is: Enabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '19.1.3.3'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '19.1.3.3'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  registry_key(hive: 'HKEY_USERS').children(/^S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]{3,}$/).map { |x| x.to_s + '\\Software\\Policies\\Microsoft\\Windows\\Control Panel\\Desktop' }.each do |entry|
    describe registry_key(entry) do
      it { should exist }
      it { should have_property 'ScreenSaverIsSecure' }
      its('ScreenSaverIsSecure') { should eq 1 }
    end
  end
end

control 'windows-363' do
  title 'Ensure \'Screen saver timeout\' is set to \'Enabled: 900 seconds or fewer, but not 0\''
  desc 'This setting specifies how much user idle time must elapse before the screen saver is launched.

  The recommended state for this setting is: Enabled: 900 seconds or fewer, but not 0.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '19.1.3.4'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '19.1.3.4'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  registry_key(hive: 'HKEY_USERS').children(/^S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]{3,}$/).map { |x| x.to_s + '\\Software\\Policies\\Microsoft\\Windows\\Control Panel\\Desktop' }.each do |entry|
    describe registry_key(entry) do
      it { should exist }
      it { should have_property 'ScreenSaveTimeOut' }
      its('ScreenSaveTimeOut') { should cmp <= 900 }
    end
  end
  registry_key(hive: 'HKEY_USERS').children(/^S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]{3,}$/).map { |x| x.to_s + '\\Software\\Policies\\Microsoft\\Windows\\Control Panel\\Desktop' }.each do |entry|
    describe registry_key(entry) do
      it { should exist }
      it { should have_property 'ScreenSaveTimeOut' }
      its('ScreenSaveTimeOut') { should_not eq 0 }
    end
  end
end

control 'windows-364' do
  title 'Ensure \'Turn off toast notifications on the lock screen\' is set to \'Enabled\''
  desc 'This policy setting turns off toast notifications on the lock screen.

  The recommended state for this setting is Enabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '19.5.1.1'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '19.5.1.1'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  registry_key(hive: 'HKEY_USERS').children(/^S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]{3,}$/).map { |x| x.to_s + '\\Software\\Policies\\Microsoft\\Windows\\CurrentVersion\\PushNotifications' }.each do |entry|
    describe registry_key(entry) do
      it { should exist }
      it { should have_property 'NoToastApplicationNotificationOnLockScreen' }
      its('NoToastApplicationNotificationOnLockScreen') { should eq 1 }
    end
  end
end

control 'windows-365' do
  title 'Ensure \'Turn off Help Experience Improvement Program\' is set to \'Enabled\''
  desc 'This policy setting specifies whether users can participate in the Help Experience Improvement program. The Help Experience Improvement program collects information about how customers use Windows Help so that Microsoft can improve it.

  The recommended state for this setting is: Enabled.'
  impact 0.5
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '19.6.5.1.1'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '19.6.5.1.1'
  tag 'level': '2'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('This Control only executes if attribute(\'level_1_or_2\') is set to 2') do
    attribute('level_1_or_2') == 2
  end
  registry_key(hive: 'HKEY_USERS').children(/^S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]{3,}$/).map { |x| x.to_s + '\\Software\\Policies\\Microsoft\\Assistance\\Client\\1.0' }.each do |entry|
    describe registry_key(entry) do
      it { should exist }
      it { should have_property 'NoImplicitFeedback' }
      its('NoImplicitFeedback') { should eq 1 }
    end
  end
end

control 'windows-366' do
  title 'Ensure \'Do not preserve zone information in file attachments\' is set to \'Disabled\''
  desc 'This policy setting allows you to manage whether Windows marks file attachments with information about their zone of origin (such as restricted, Internet, intranet, local). This requires NTFS in order to function correctly, and will fail without notice on FAT32. By not preserving the zone information, Windows cannot make proper risk assessments.

  The recommended state for this setting is: Disabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '19.7.4.1'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '19.7.4.1'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  registry_key(hive: 'HKEY_USERS').children(/^S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]{3,}$/).map { |x| x.to_s + '\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Attachments' }.each do |entry|
    describe registry_key(entry) do
      it { should exist }
      it { should have_property 'SaveZoneInformation' }
      its('SaveZoneInformation') { should eq 2 }
    end
  end
end

control 'windows-367' do
  title 'Ensure \'Notify antivirus programs when opening attachments\' is set to \'Enabled\''
  desc 'This policy setting allows you to manage the behavior for notifying registered antivirus programs. If multiple programs are registered, they will all be notified.

  The recommended state for this setting is: Enabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '19.7.4.2'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '19.7.4.2'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  registry_key(hive: 'HKEY_USERS').children(/^S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]{3,}$/).map { |x| x.to_s + '\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Attachments' }.each do |entry|
    describe registry_key(entry) do
      it { should exist }
      it { should have_property 'ScanWithAntiVirus' }
      its('ScanWithAntiVirus') { should eq 3 }
    end
  end
end

control 'windows-368' do
  title 'Ensure \'Configure Windows spotlight on Lock Screen\' is set to Disabled\''
  desc 'This policy setting lets you configure Windows Spotlight on the lock screen.

  The recommended state for this setting is: Disabled.'
  impact 0.5
  tag 'windows': %w[2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '19.7.7.1'
  tag 'level': '2'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('Only for Windows Server 2016, 2019 and if attribute(\'level_1_or_2\') is set to 2') do
    (((os[:name].include? '2016') || (os[:name].include? '2019')) && attribute('level_1_or_2') == 2)
  end
  registry_key(hive: 'HKEY_USERS').children(/^S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]{3,}$/).map { |x| x.to_s + '\\Software\\Policies\\Microsoft\\Windows\\CloudContent' }.each do |entry|
    describe registry_key(entry) do
      it { should exist }
      it { should have_property 'ConfigureWindowsSpotlight' }
      its('ConfigureWindowsSpotlight') { should eq 2 }
    end
  end
end

control 'windows-369' do
  title 'Ensure \'Do not suggest third-party content in Windows spotlight\' is set to \'Enabled\''
  desc 'This policy setting determines whether Windows will suggest apps and content from third-party software publishers.

  The recommended state for this setting is: Enabled.'
  impact 1.0
  tag 'windows': %w[2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '19.7.7.2'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('Only for Windows Server 2016, 2019') do
    ((os[:name].include? '2016') || (os[:name].include? '2019'))
  end
  registry_key(hive: 'HKEY_USERS').children(/^S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]{3,}$/).map { |x| x.to_s + '\\Software\\Policies\\Microsoft\\Windows\\CloudContent' }.each do |entry|
    describe registry_key(entry) do
      it { should exist }
      it { should have_property 'DisableThirdPartySuggestions' }
      its('DisableThirdPartySuggestions') { should eq 1 }
    end
  end
end

control 'windows-370' do
  title 'Ensure \'Do not use diagnostic data for tailored experiences\' is set to \'Enabled\''
  desc 'This setting determines if Windows can use diagnostic data to provide tailored experiences to the user.

  The recommended state for this setting is: Enabled.'
  impact 0.5
  tag 'windows': %w[2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '19.7.7.3'
  tag 'level': '2'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('Only for Windows Server 2016, 2019 and if attribute(\'level_1_or_2\') is set to 2') do
    (((os[:name].include? '2016') || (os[:name].include? '2019')) && attribute('level_1_or_2') == 2)
  end
  registry_key(hive: 'HKEY_USERS').children(/^S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]{3,}$/).map { |x| x.to_s + '\\Software\\Policies\\Microsoft\\Windows\\CloudContent' }.each do |entry|
    describe registry_key(entry) do
      it { should exist }
      it { should have_property 'DisableWindowsSpotlightFeatures' }
      its('DisableWindowsSpotlightFeatures') { should eq 1 }
    end
  end
end

control 'windows-371' do
  title 'Ensure \'Turn off all Windows spotlight features\' is set to \'Enabled\''
  desc 'This policy setting lets you turn off all Windows Spotlight features at once.

  The recommended state for this setting is: Enabled.'
  impact 0.5
  tag 'windows': %w[2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '19.7.7.4'
  tag 'level': '2'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('Only for Windows Server 2016, 2019 and if attribute(\'level_1_or_2\') is set to 2') do
    (((os[:name].include? '2016') || (os[:name].include? '2019')) && attribute('level_1_or_2') == 2)
  end
  registry_key(hive: 'HKEY_USERS').children(/^S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]{3,}$/).map { |x| x.to_s + '\\Software\\Policies\\Microsoft\\Windows\\CloudContent' }.each do |entry|
    describe registry_key(entry) do
      it { should exist }
      it { should have_property 'DisableWindowsSpotlightFeatures' }
      its('DisableWindowsSpotlightFeatures') { should eq 1 }
    end
  end
end

control 'windows-372' do
  title 'Ensure \'Prevent users from sharing files within their profile.\' is set to \'Enabled\''
  desc 'This policy setting specifies whether users can share files within their profile. By default users are allowed to share files within their profile to other users on their network after an administrator opts in the computer. An administrator can opt in the computer by using the sharing wizard to share a file within their profile.

  The recommended state for this setting is: Enabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '19.7.26.1'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '19.7.26.1'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  registry_key(hive: 'HKEY_USERS').children(/^S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]{3,}$/).map { |x| x.to_s + '\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer' }.each do |entry|
    describe registry_key(entry) do
      it { should exist }
      it { should have_property 'NoInplaceSharing' }
      its('NoInplaceSharing') { should eq 1 }
    end
  end
end

control 'windows-373' do
  title 'Ensure \'Always install with elevated privileges\' is set to \'Disabled\''
  desc 'This setting controls whether or not Windows Installer should use system permissions when it installs any program on the system.

  **Note:** This setting appears both in the Computer Configuration and User Configuration folders. To make this setting effective, you must enable the setting in both folders.

  **Caution:** If enabled, skilled users can take advantage of the permissions this setting grants to change their privileges and gain permanent access to restricted files and folders. Note that the User Configuration version of this setting is not guaranteed to be secure.

  The recommended state for this setting is: Disabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '19.7.40.1'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '19.7.40.1'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  registry_key(hive: 'HKEY_USERS').children(/^S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]{3,}$/).map { |x| x.to_s + '\\Software\\Policies\\Microsoft\\Windows\\Installer' }.each do |entry|
    describe registry_key(entry) do
      it { should exist }
      it { should have_property 'AlwaysInstallElevated' }
      its('AlwaysInstallElevated') { should eq 0 }
    end
  end
end

control 'windows-374' do
  title 'Ensure \'Prevent Codec Download\' is set to \'Enabled\''
  desc 'This setting controls whether Windows Media Player is allowed to download additional codecs for decoding media files it does not already understand.

  The recommended state for this setting is: Enabled.'
  impact 0.5
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '19.7.44.2.1'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '19.7.44.2.1'
  tag 'level': '2'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('This Control only executes if attribute(\'level_1_or_2\') is set to 2') do
    attribute('level_1_or_2') == 2
  end
  registry_key(hive: 'HKEY_USERS').children(/^S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]{3,}$/).map { |x| x.to_s + '\\Software\\Policies\\Microsoft\\WindowsMediaPlayer' }.each do |entry|
    describe registry_key(entry) do
      it { should exist }
      it { should have_property 'PreventCodecDownload' }
      its('PreventCodecDownload') { should eq 1 }
    end
  end
end

# Controls from best practice ms-technet
control 'windows-901' do
  title 'Ensure to disable AJRouter services'
  desc 'Routes AllJoyn messages for the local AllJoyn clients. If this service is stopped the AllJoyn clients that do not have their own bundled routers will be unable to run.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'microsoft': 'technet'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration', 'SYS.1.2.2.M8', 'Schutz der Systemintegrität']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Microsoft', url: 'https://docs.microsoft.com/de-de/windows-server/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server'
  ref 'Github', url: 'https://github.com/MicrosoftDocs/windowsserverdocs/blob/master/WindowsServerDocs/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server.md'
  only_if('AJRouter is not installed.') do
    service('AJRouter').installed?
  end
  describe service('AJRouter') do
    it { should be_installed }
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

control 'windows-902' do
  title 'Ensure to disable ALG Service'
  desc 'Provides support for third-party protocol plug-ins for Internet Connection Sharing'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'microsoft': 'technet'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration', 'SYS.1.2.2.M8', 'Schutz der Systemintegrität']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Microsoft', url: 'https://docs.microsoft.com/de-de/windows-server/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server'
  ref 'Github', url: 'https://github.com/MicrosoftDocs/windowsserverdocs/blob/master/WindowsServerDocs/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server.md'
  only_if('ALG is not installed.') do
    service('ALG').installed?
  end
  describe service('ALG') do
    it { should be_installed }
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

control 'windows-903' do
  title 'Ensure to disable AppMgmt service'
  desc 'Processes installation, removal, and enumeration requests for software deployed through Group Policy. If the service is disabled, users will be unable to install, remove, or enumerate software deployed through Group Policy. If this service is disabled, any services that explicitly depend on it will fail to start.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'microsoft': 'technet'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration', 'SYS.1.2.2.M8', 'Schutz der Systemintegrität']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Microsoft', url: 'https://docs.microsoft.com/de-de/windows-server/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server'
  ref 'Github', url: 'https://github.com/MicrosoftDocs/windowsserverdocs/blob/master/WindowsServerDocs/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server.md'
  only_if('AppMgmt is not installed.') do
    service('AppMgmt').installed?
  end
  describe service('AppMgmt') do
    it { should be_installed }
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

control 'windows-904' do
  title 'Ensure to disable AudioEndpointBuilder service'
  desc 'Manages audio devices for the Windows Audio service. If this service is stopped, audio devices and effects will not function properly. If this service is disabled, any services that explicitly depend on it will fail to start'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'microsoft': 'technet'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration', 'SYS.1.2.2.M8', 'Schutz der Systemintegrität']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Microsoft', url: 'https://docs.microsoft.com/de-de/windows-server/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server'
  ref 'Github', url: 'https://github.com/MicrosoftDocs/windowsserverdocs/blob/master/WindowsServerDocs/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server.md'
  only_if('AudioEndpointBuilder is not installed.') do
    service('AudioEndpointBuilder').installed?
  end
  describe service('AudioEndpointBuilder') do
    it { should be_installed }
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

control 'windows-905' do
  title 'Ensure to disable Audiosrv service'
  desc 'Manages audio for Windows-based programs. If this service is stopped, audio devices and effects will not function properly. If this service is disabled, any services that explicitly depend on it will fail to start'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'microsoft': 'technet'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration', 'SYS.1.2.2.M8', 'Schutz der Systemintegrität']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Microsoft', url: 'https://docs.microsoft.com/de-de/windows-server/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server'
  ref 'Github', url: 'https://github.com/MicrosoftDocs/windowsserverdocs/blob/master/WindowsServerDocs/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server.md'
  only_if('Audiosrv is not installed.') do
    service('Audiosrv').installed?
  end
  describe service('Audiosrv') do
    it { should be_installed }
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

control 'windows-906' do
  title 'Ensure to disable AxInstSV service'
  desc 'Provides User Account Control validation for the installation of ActiveX controls from the Internet and enables management of ActiveX control installation based on Group Policy settings. This service is started on demand and if disabled the installation of ActiveX controls will behave according to default browser settings.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'microsoft': 'technet'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration', 'SYS.1.2.2.M8', 'Schutz der Systemintegrität']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Microsoft', url: 'https://docs.microsoft.com/de-de/windows-server/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server'
  ref 'Github', url: 'https://github.com/MicrosoftDocs/windowsserverdocs/blob/master/WindowsServerDocs/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server.md'
  only_if('AxInstSV is not installed.') do
    service('AxInstSV').installed?
  end
  describe service('AxInstSV') do
    it { should be_installed }
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

control 'windows-907' do
  title 'Ensure to disable Bthserv service'
  desc 'The Bluetooth service supports discovery and association of remote Bluetooth devices. Stopping or disabling this service may cause already installed Bluetooth devices to fail to operate properly and prevent new devices from being discovered or associated.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'microsoft': 'technet'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration', 'SYS.1.2.2.M8', 'Schutz der Systemintegrität']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Microsoft', url: 'https://docs.microsoft.com/de-de/windows-server/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server'
  ref 'Github', url: 'https://github.com/MicrosoftDocs/windowsserverdocs/blob/master/WindowsServerDocs/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server.md'
  only_if('Bthserv is not installed.') do
    service('Bthserv').installed?
  end
  describe service('Bthserv') do
    it { should be_installed }
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

control 'windows-908' do
  title 'Ensure to disable DcpSvc service'
  desc 'The DCP (Data Collection and Publishing) service supports first-party apps to upload data to cloud.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'microsoft': 'technet'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration', 'SYS.1.2.2.M8', 'Schutz der Systemintegrität']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Microsoft', url: 'https://docs.microsoft.com/de-de/windows-server/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server'
  ref 'Github', url: 'https://github.com/MicrosoftDocs/windowsserverdocs/blob/master/WindowsServerDocs/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server.md'
  only_if('DcpSvc is not installed.') do
    service('DcpSvc').installed?
  end
  describe service('DcpSvc') do
    it { should be_installed }
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

control 'windows-909' do
  title 'Ensure to disable DevQueryBroker service'
  desc 'Enables apps to discover devices with a backgroud task'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'microsoft': 'technet'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration', 'SYS.1.2.2.M8', 'Schutz der Systemintegrität']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Microsoft', url: 'https://docs.microsoft.com/de-de/windows-server/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server'
  ref 'Github', url: 'https://github.com/MicrosoftDocs/windowsserverdocs/blob/master/WindowsServerDocs/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server.md'
  only_if('DevQueryBroker is not installed.') do
    service('DevQueryBroker').installed?
  end
  describe service('DevQueryBroker') do
    it { should be_installed }
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

control 'windows-910' do
  title 'Ensure to disable DPS service'
  desc 'The Diagnostic Policy Service enables problem detection, troubleshooting and resolution for Windows components. If this service is stopped, diagnostics will no longer function.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'microsoft': 'technet'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration', 'SYS.1.2.2.M8', 'Schutz der Systemintegrität']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Microsoft', url: 'https://docs.microsoft.com/de-de/windows-server/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server'
  ref 'Github', url: 'https://github.com/MicrosoftDocs/windowsserverdocs/blob/master/WindowsServerDocs/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server.md'
  only_if('DPS is not installed.') do
    service('DPS').installed?
  end
  describe service('DPS') do
    it { should be_installed }
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

control 'windows-911' do
  title 'Ensure to disable DiagTrack service'
  desc 'The Connected User Experiences and Telemetry service enables features that support in-application and connected user experiences. Additionally, this service manages the event-driven collection and transmission of diagnostic and usage information (used to improve the experience and quality of the Windows Platform) when the diagnostics and usage privacy option settings are enabled under Feedback and Diagnostics.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'microsoft': 'technet'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Microsoft', url: 'https://docs.microsoft.com/de-de/windows-server/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server'
  ref 'Github', url: 'https://github.com/MicrosoftDocs/windowsserverdocs/blob/master/WindowsServerDocs/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server.md'
  only_if('DiagTrack is not installed.') do
    service('DiagTrack').installed?
  end
  describe service('DiagTrack') do
    it { should be_installed }
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

control 'windows-912' do
  title 'Ensure to disable Dmwappushservice service'
  desc 'WAP Push Message Routing Service'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'microsoft': 'technet'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Microsoft', url: 'https://docs.microsoft.com/de-de/windows-server/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server'
  ref 'Github', url: 'https://github.com/MicrosoftDocs/windowsserverdocs/blob/master/WindowsServerDocs/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server.md'
  only_if('Dmwappushservice is not installed.') do
    service('Dmwappushservice').installed?
  end
  describe service('Dmwappushservice') do
    it { should be_installed }
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

control 'windows-913' do
  title 'Ensure to disable FrameServer service'
  desc 'Enables multiple clients to access video frames from camera devices.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'microsoft': 'technet'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Microsoft', url: 'https://docs.microsoft.com/de-de/windows-server/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server'
  ref 'Github', url: 'https://github.com/MicrosoftDocs/windowsserverdocs/blob/master/WindowsServerDocs/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server.md'
  only_if('FrameServer is not installed.') do
    service('FrameServer').installed?
  end
  describe service('FrameServer') do
    it { should be_installed }
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

control 'windows-914' do
  title 'Ensure to disable hidserv service'
  desc 'Activates and maintains the use of hot buttons on keyboards, remote controls, and other multimedia devices. It is recommended that you keep this service running.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'microsoft': 'technet'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration', 'SYS.1.2.2.M8', 'Schutz der Systemintegrität']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Microsoft', url: 'https://docs.microsoft.com/de-de/windows-server/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server'
  ref 'Github', url: 'https://github.com/MicrosoftDocs/windowsserverdocs/blob/master/WindowsServerDocs/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server.md'
  only_if('hidserv is not installed.') do
    service('hidserv').installed?
  end
  describe service('hidserv') do
    it { should be_installed }
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

control 'windows-915' do
  title 'Ensure to disable Icssvc service'
  desc 'Provides the ability to share a cellular data connection with another device.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'microsoft': 'technet'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Microsoft', url: 'https://docs.microsoft.com/de-de/windows-server/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server'
  ref 'Github', url: 'https://github.com/MicrosoftDocs/windowsserverdocs/blob/master/WindowsServerDocs/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server.md'
  only_if('Icssvc is not installed.') do
    service('Icssvc').installed?
  end
  describe service('Icssvc') do
    it { should be_installed }
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

control 'windows-916' do
  title 'Ensure to disable lfsvc service'
  desc 'This service monitors the current location of the system and manages geofences (a geographical location with associated events). If you turn off this service, applications will be unable to use or receive notifications for geolocation or geofences.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'microsoft': 'technet'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Microsoft', url: 'https://docs.microsoft.com/de-de/windows-server/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server'
  ref 'Github', url: 'https://github.com/MicrosoftDocs/windowsserverdocs/blob/master/WindowsServerDocs/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server.md'
  only_if('lfsvc is not installed.') do
    service('lfsvc').installed?
  end
  describe service('lfsvc') do
    it { should be_installed }
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

control 'windows-917' do
  title 'Ensure to disable LicenseManager service'
  desc 'Provides infrastructure support for the Microsoft Store. This service is started on demand and if disabled then content acquired through the Microsoft Store will not function properly.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'microsoft': 'technet'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration', 'SYS.1.2.2.M8', 'Schutz der Systemintegrität']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Microsoft', url: 'https://docs.microsoft.com/de-de/windows-server/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server'
  ref 'Github', url: 'https://github.com/MicrosoftDocs/windowsserverdocs/blob/master/WindowsServerDocs/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server.md'
  only_if('LicenseManager is not installed.') do
    service('LicenseManager').installed?
  end
  describe service('LicenseManager') do
    it { should be_installed }
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

control 'windows-918' do
  title 'Ensure to disable MapsBroker service'
  desc 'Windows service for application access to downloaded maps. This service is started on-demand by application accessing downloaded maps. Disabling this service will prevent apps from accessing maps.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'microsoft': 'technet'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration', 'SYS.1.2.2.M8', 'Schutz der Systemintegrität']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Microsoft', url: 'https://docs.microsoft.com/de-de/windows-server/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server'
  ref 'Github', url: 'https://github.com/MicrosoftDocs/windowsserverdocs/blob/master/WindowsServerDocs/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server.md'
  only_if('MapsBroker is not installed.') do
    service('MapsBroker').installed?
  end
  describe service('MapsBroker') do
    it { should be_installed }
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

control 'windows-919' do
  title 'Ensure to disable NcbService service'
  desc 'Brokers connections that allow Microsoft Store Apps to receive notifications from the internet.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'microsoft': 'technet'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Microsoft', url: 'https://docs.microsoft.com/de-de/windows-server/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server'
  ref 'Github', url: 'https://github.com/MicrosoftDocs/windowsserverdocs/blob/master/WindowsServerDocs/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server.md'
  only_if('NcbService is not installed.') do
    service('NcbService').installed?
  end
  describe service('NcbService') do
    it { should be_installed }
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

control 'windows-920' do
  title 'Ensure to disable PcaSvc service'
  desc 'This service provides support for the Program Compatibility Assistant (PCA). PCA monitors programs installed and run by the user and detects known compatibility problems. If this service is stopped, PCA will not function properly.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'microsoft': 'technet'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration', 'SYS.1.2.2.M8', 'Schutz der Systemintegrität']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Microsoft', url: 'https://docs.microsoft.com/de-de/windows-server/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server'
  ref 'Github', url: 'https://github.com/MicrosoftDocs/windowsserverdocs/blob/master/WindowsServerDocs/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server.md'
  only_if('PcaSvc is not installed.') do
    service('PcaSvc').installed?
  end
  describe service('PcaSvc') do
    it { should be_installed }
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

control 'windows-921' do
  title 'Ensure to disable PhoneSvc service'
  desc 'Manages the telephony state on the device'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'microsoft': 'technet'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration', 'SYS.1.2.2.M8', 'Schutz der Systemintegrität']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Microsoft', url: 'https://docs.microsoft.com/de-de/windows-server/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server'
  ref 'Github', url: 'https://github.com/MicrosoftDocs/windowsserverdocs/blob/master/WindowsServerDocs/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server.md'
  only_if('PhoneSvc is not installed.') do
    service('PhoneSvc').installed?
  end
  describe service('PhoneSvc') do
    it { should be_installed }
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

control 'windows-922' do
  title 'Ensure to disable PrintNotify service'
  desc 'This service opens custom printer dialog boxes and handles notifications from a remote print server or a printer. If you turn off this service, you won\'t be able to see printer extensions or notifications.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'microsoft': 'technet'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration', 'SYS.1.2.2.M8', 'Schutz der Systemintegrität']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Microsoft', url: 'https://docs.microsoft.com/de-de/windows-server/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server'
  ref 'Github', url: 'https://github.com/MicrosoftDocs/windowsserverdocs/blob/master/WindowsServerDocs/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server.md'
  only_if('PrintNotify is not installed.') do
    service('PrintNotify').installed?
  end
  describe service('PrintNotify') do
    it { should be_installed }
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

control 'windows-923' do
  title 'Ensure to disable qWave service'
  desc 'Quality Windows Audio Video Experience (qWave) is a networking platform for Audio Video (AV) streaming applications on IP home networks. qWave enhances AV streaming performance and reliability by ensuring network quality-of-service (QoS) for AV applications. It provides mechanisms for admission control, run time monitoring and enforcement, application feedback, and traffic prioritization.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'microsoft': 'technet'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Microsoft', url: 'https://docs.microsoft.com/de-de/windows-server/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server'
  ref 'Github', url: 'https://github.com/MicrosoftDocs/windowsserverdocs/blob/master/WindowsServerDocs/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server.md'
  only_if('qWave is not installed.') do
    service('qWave').installed?
  end
  describe service('qWave') do
    it { should be_installed }
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

control 'windows-924' do
  title 'Ensure to disable RasAuto service'
  desc 'Creates a connection to a remote network whenever a program references a remote DNS or NetBIOS name or address.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'microsoft': 'technet'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration', 'SYS.1.2.2.M8', 'Schutz der Systemintegrität']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Microsoft', url: 'https://docs.microsoft.com/de-de/windows-server/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server'
  ref 'Github', url: 'https://github.com/MicrosoftDocs/windowsserverdocs/blob/master/WindowsServerDocs/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server.md'
  only_if('RasAuto is not installed.') do
    service('RasAuto').installed?
  end
  describe service('RasAuto') do
    it { should be_installed }
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

control 'windows-925' do
  title 'Ensure to disable RasMan service'
  desc 'Manages dial-up and virtual private network (VPN) connections from this computer to the Internet or other remote networks. If this service is disabled, any services that explicitly depend on it will fail to start.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'microsoft': 'technet'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Microsoft', url: 'https://docs.microsoft.com/de-de/windows-server/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server'
  ref 'Github', url: 'https://github.com/MicrosoftDocs/windowsserverdocs/blob/master/WindowsServerDocs/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server.md'
  only_if('RasMan is not installed.') do
    service('RasMan').installed?
  end
  describe service('RasMan') do
    it { should be_installed }
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

control 'windows-926' do
  title 'Ensure to disable RmSvc service'
  desc 'Radio Management and Airplane Mode Service'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'microsoft': 'technet'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration', 'SYS.1.2.2.M8', 'Schutz der Systemintegrität']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Microsoft', url: 'https://docs.microsoft.com/de-de/windows-server/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server'
  ref 'Github', url: 'https://github.com/MicrosoftDocs/windowsserverdocs/blob/master/WindowsServerDocs/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server.md'
  only_if('RmSvc is not installed.') do
    service('RmSvc').installed?
  end
  describe service('RmSvc') do
    it { should be_installed }
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

control 'windows-927' do
  title 'Ensure to disable RpcLocator service'
  desc 'In Windows 2003 and earlier versions of Windows, the Remote Procedure Call (RPC) Locator service manages the RPC name service database. In Windows Vista and later versions of Windows, this service does not provide any functionality and is present for application compatibility.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'microsoft': 'technet'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration', 'SYS.1.2.2.M8', 'Schutz der Systemintegrität']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Microsoft', url: 'https://docs.microsoft.com/de-de/windows-server/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server'
  ref 'Github', url: 'https://github.com/MicrosoftDocs/windowsserverdocs/blob/master/WindowsServerDocs/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server.md'
  only_if('RpcLocator is not installed.') do
    service('RpcLocator').installed?
  end
  describe service('RpcLocator') do
    it { should be_installed }
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

control 'windows-928' do
  title 'Ensure to disable RSoPProv service'
  desc 'Provides a network service that processes requests to simulate application of Group Policy settings for a target user or computer in various situations and computes the Resultant Set of Policy settings.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'microsoft': 'technet'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration', 'SYS.1.2.2.M8', 'Schutz der Systemintegrität']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Microsoft', url: 'https://docs.microsoft.com/de-de/windows-server/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server'
  ref 'Github', url: 'https://github.com/MicrosoftDocs/windowsserverdocs/blob/master/WindowsServerDocs/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server.md'
  only_if('RSoPProv is not installed.') do
    service('RSoPProv').installed?
  end
  describe service('RSoPProv') do
    it { should be_installed }
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

control 'windows-929' do
  title 'Ensure to disable Sacsvr service'
  desc 'Allows administrators to remotely access a command prompt using Emergency Management Services.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'microsoft': 'technet'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration', 'SYS.1.2.2.M8', 'Schutz der Systemintegrität']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Microsoft', url: 'https://docs.microsoft.com/de-de/windows-server/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server'
  ref 'Github', url: 'https://github.com/MicrosoftDocs/windowsserverdocs/blob/master/WindowsServerDocs/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server.md'
  only_if('Sacsvr is not installed.') do
    service('Sacsvr').installed?
  end
  describe service('Sacsvr') do
    it { should be_installed }
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

control 'windows-930' do
  title 'Ensure to disable ScDeviceEnum service'
  desc 'Creates software device nodes for all smart card readers accessible to a given session. If this service is disabled, WinRT APIs will not be able to enumerate smart card readers.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'microsoft': 'technet'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration', 'SYS.1.2.2.M8', 'Schutz der Systemintegrität']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Microsoft', url: 'https://docs.microsoft.com/de-de/windows-server/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server'
  ref 'Github', url: 'https://github.com/MicrosoftDocs/windowsserverdocs/blob/master/WindowsServerDocs/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server.md'
  only_if('ScDeviceEnum is not installed.') do
    service('ScDeviceEnum').installed?
  end
  describe service('ScDeviceEnum') do
    it { should be_installed }
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

control 'windows-931' do
  title 'Ensure to disable SCPolicySvc service'
  desc 'Allows the system to be configured to lock the user desktop upon smart card removal.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'microsoft': 'technet'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Microsoft', url: 'https://docs.microsoft.com/de-de/windows-server/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server'
  ref 'Github', url: 'https://github.com/MicrosoftDocs/windowsserverdocs/blob/master/WindowsServerDocs/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server.md'
  only_if('SCPolicySvc is not installed.') do
    service('SCPolicySvc').installed?
  end
  describe service('SCPolicySvc') do
    it { should be_installed }
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

control 'windows-932' do
  title 'Ensure to disable SensorDataService service'
  desc 'Delivers data from a variety of sensors'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'microsoft': 'technet'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Microsoft', url: 'https://docs.microsoft.com/de-de/windows-server/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server'
  ref 'Github', url: 'https://github.com/MicrosoftDocs/windowsserverdocs/blob/master/WindowsServerDocs/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server.md'
  only_if('SensorDataService is not installed.') do
    service('SensorDataService').installed?
  end
  describe service('SensorDataService') do
    it { should be_installed }
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

control 'windows-933' do
  title 'Ensure to disable SensorService service'
  desc 'A service for sensors that manages different sensors\' functionality. Manages Simple Device Orientation (SDO) and History for sensors. Loads the SDO sensor that reports device orientation changes. If this service is stopped or disabled, the SDO sensor will not be loaded and so auto-rotation will not occur. History collection from Sensors will also be stopped.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'microsoft': 'technet'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Microsoft', url: 'https://docs.microsoft.com/de-de/windows-server/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server'
  ref 'Github', url: 'https://github.com/MicrosoftDocs/windowsserverdocs/blob/master/WindowsServerDocs/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server.md'
  only_if('SensorService is not installed.') do
    service('SensorService').installed?
  end
  describe service('SensorService') do
    it { should be_installed }
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

control 'windows-934' do
  title 'Ensure to disable SensrSvc service'
  desc 'Monitors various sensors in order to expose data and adapt to system and user state. If this service is stopped or disabled, the display brightness will not adapt to lighting conditions. Stopping this service may affect other system functionality and features as well.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'microsoft': 'technet'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Microsoft', url: 'https://docs.microsoft.com/de-de/windows-server/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server'
  ref 'Github', url: 'https://github.com/MicrosoftDocs/windowsserverdocs/blob/master/WindowsServerDocs/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server.md'
  only_if('SensrSvc is not installed.') do
    service('SensrSvc').installed?
  end
  describe service('SensrSvc') do
    it { should be_installed }
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

control 'windows-935' do
  title 'Ensure to disable SharedAccess service'
  desc 'Provides network address translation, addressing, name resolution and/or intrusion prevention services for a home or small office network.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'microsoft': 'technet'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Microsoft', url: 'https://docs.microsoft.com/de-de/windows-server/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server'
  ref 'Github', url: 'https://github.com/MicrosoftDocs/windowsserverdocs/blob/master/WindowsServerDocs/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server.md'
  only_if('SharedAccess is not installed.') do
    service('SharedAccess').installed?
  end
  describe service('SharedAccess') do
    it { should be_installed }
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

control 'windows-936' do
  title 'Ensure to disable ShellHWDetection service'
  desc 'Provides notifications for AutoPlay hardware events.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'microsoft': 'technet'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Microsoft', url: 'https://docs.microsoft.com/de-de/windows-server/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server'
  ref 'Github', url: 'https://github.com/MicrosoftDocs/windowsserverdocs/blob/master/WindowsServerDocs/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server.md'
  only_if('ShellHWDetection is not installed.') do
    service('ShellHWDetection').installed?
  end
  describe service('ShellHWDetection') do
    it { should be_installed }
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

control 'windows-937' do
  title 'Ensure to disable SSDPSRV service'
  desc 'Discovers networked devices and services that use the SSDP discovery protocol, such as UPnP devices. Also announces SSDP devices and services running on the local computer. If this service is stopped, SSDP-based devices will not be discovered. If this service is disabled, any services that explicitly depend on it will fail to start.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'microsoft': 'technet'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']

  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Microsoft', url: 'https://docs.microsoft.com/de-de/windows-server/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server'
  ref 'Github', url: 'https://github.com/MicrosoftDocs/windowsserverdocs/blob/master/WindowsServerDocs/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server.md'
  only_if('SSDPSRV is not installed.') do
    service('SSDPSRV').installed?
  end
  describe service('SSDPSRV') do
    it { should be_installed }
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

control 'windows-938' do
  title 'Ensure to disable stisvc service'
  desc 'Provides image acquisition services for scanners and cameras'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'microsoft': 'technet'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Microsoft', url: 'https://docs.microsoft.com/de-de/windows-server/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server'
  ref 'Github', url: 'https://github.com/MicrosoftDocs/windowsserverdocs/blob/master/WindowsServerDocs/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server.md'
  only_if('stisvc is not installed.') do
    service('stisvc').installed?
  end
  describe service('stisvc') do
    it { should be_installed }
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

control 'windows-939' do
  title 'Ensure to disable TabletInputService service'
  desc 'Enables Touch Keyboard and Handwriting Panel pen and ink functionality'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'microsoft': 'technet'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Microsoft', url: 'https://docs.microsoft.com/de-de/windows-server/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server'
  ref 'Github', url: 'https://github.com/MicrosoftDocs/windowsserverdocs/blob/master/WindowsServerDocs/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server.md'
  only_if('TabletInputService is not installed.') do
    service('TabletInputService').installed?
  end
  describe service('TabletInputService') do
    it { should be_installed }
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

control 'windows-940' do
  title 'Ensure to disable upnphost service'
  desc 'Allows UPnP devices to be hosted on this computer. If this service is stopped, any hosted UPnP devices will stop functioning and no additional hosted devices can be added. If this service is disabled, any services that explicitly depend on it will fail to start.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'microsoft': 'technet'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Microsoft', url: 'https://docs.microsoft.com/de-de/windows-server/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server'
  ref 'Github', url: 'https://github.com/MicrosoftDocs/windowsserverdocs/blob/master/WindowsServerDocs/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server.md'
  only_if('upnphost is not installed.') do
    service('upnphost').installed?
  end
  describe service('upnphost') do
    it { should be_installed }
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

control 'windows-941' do
  title 'Ensure to disable WalletService service'
  desc 'Hosts objects used by clients of the wallet'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'microsoft': 'technet'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Microsoft', url: 'https://docs.microsoft.com/de-de/windows-server/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server'
  ref 'Github', url: 'https://github.com/MicrosoftDocs/windowsserverdocs/blob/master/WindowsServerDocs/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server.md'
  only_if('WalletService is not installed.') do
    service('WalletService').installed?
  end
  describe service('WalletService') do
    it { should be_installed }
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

control 'windows-942' do
  title 'Ensure to disable WbioSrvc service'
  desc 'The Windows biometric service gives client applications the ability to capture, compare, manipulate, and store biometric data without gaining direct access to any biometric hardware or samples. The service is hosted in a privileged SVCHOST process.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'microsoft': 'technet'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Microsoft', url: 'https://docs.microsoft.com/de-de/windows-server/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server'
  ref 'Github', url: 'https://github.com/MicrosoftDocs/windowsserverdocs/blob/master/WindowsServerDocs/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server.md'
  only_if('WbioSrvc is not installed.') do
    service('WbioSrvc').installed?
  end
  describe service('WbioSrvc') do
    it { should be_installed }
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

control 'windows-943' do
  title 'Ensure to disable wercplsupport service'
  desc 'This service provides support for viewing, sending and deletion of system-level problem reports for the Problem Reports and Solutions control panel.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'microsoft': 'technet'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Microsoft', url: 'https://docs.microsoft.com/de-de/windows-server/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server'
  ref 'Github', url: 'https://github.com/MicrosoftDocs/windowsserverdocs/blob/master/WindowsServerDocs/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server.md'
  only_if('wercplsupport is not installed.') do
    service('wercplsupport').installed?
  end
  describe service('wercplsupport') do
    it { should be_installed }
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

control 'windows-944' do
  title 'Ensure to disable WiaRpc service'
  desc 'Launches applications associated with still image acquisition events.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'microsoft': 'technet'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Microsoft', url: 'https://docs.microsoft.com/de-de/windows-server/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server'
  ref 'Github', url: 'https://github.com/MicrosoftDocs/windowsserverdocs/blob/master/WindowsServerDocs/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server.md'
  only_if('WiaRpc is not installed.') do
    service('WiaRpc').installed?
  end
  describe service('WiaRpc') do
    it { should be_installed }
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

control 'windows-945' do
  title 'Ensure to disable wisvc service'
  desc 'Ensure to disable Windows Insider Service service'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'microsoft': 'technet'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Microsoft', url: 'https://docs.microsoft.com/de-de/windows-server/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server'
  ref 'Github', url: 'https://github.com/MicrosoftDocs/windowsserverdocs/blob/master/WindowsServerDocs/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server.md'
  only_if('wisvc is not installed.') do
    service('wisvc').installed?
  end
  describe service('wisvc') do
    it { should be_installed }
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

control 'windows-946' do
  title 'Ensure to disable wlidsvc service'
  desc 'Enables user sign-in through Microsoft account identity services. If this service is stopped, users will not be able to log on to the computer with their Microsoft account.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'microsoft': 'technet'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration', 'SYS.1.2.2.M8', 'Schutz der Systemintegrität']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Microsoft', url: 'https://docs.microsoft.com/de-de/windows-server/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server'
  ref 'Github', url: 'https://github.com/MicrosoftDocs/windowsserverdocs/blob/master/WindowsServerDocs/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server.md'
  only_if('wlidsvc is not installed.') do
    service('wlidsvc').installed?
  end
  describe service('wlidsvc') do
    it { should be_installed }
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

control 'windows-947' do
  title 'Ensure to disable WPDBusEnum service'
  desc 'Enforces group policy for removable mass-storage devices. Enables applications such as Windows Media Player and Image Import Wizard to transfer and synchronize content using removable mass-storage devices.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'microsoft': 'technet'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Microsoft', url: 'https://docs.microsoft.com/de-de/windows-server/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server'
  ref 'Github', url: 'https://github.com/MicrosoftDocs/windowsserverdocs/blob/master/WindowsServerDocs/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server.md'
  only_if('WPDBusEnum is not installed.') do
    service('WPDBusEnum').installed?
  end
  describe service('WPDBusEnum') do
    it { should be_installed }
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

control 'windows-948' do
  title 'Ensure to disable WpnService service'
  desc 'This service runs in session 0 and hosts the notification platform and connection provider which handles the connection between the device and WNS server.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'microsoft': 'technet'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Microsoft', url: 'https://docs.microsoft.com/de-de/windows-server/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server'
  ref 'Github', url: 'https://github.com/MicrosoftDocs/windowsserverdocs/blob/master/WindowsServerDocs/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server.md'
  only_if('WpnService is not installed.') do
    service('WpnService').installed?
  end
  describe service('WpnService') do
    it { should be_installed }
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

control 'windows-949' do
  title 'Ensure to disable XblAuthManager service'
  desc 'Provides authentication and authorization services for interacting with Xbox Live. If this service is stopped, some applications may not operate correctly.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'microsoft': 'technet'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Microsoft', url: 'https://docs.microsoft.com/de-de/windows-server/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server'
  ref 'Github', url: 'https://github.com/MicrosoftDocs/windowsserverdocs/blob/master/WindowsServerDocs/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server.md'
  only_if('XblAuthManager is not installed.') do
    service('XblAuthManager').installed?
  end
  describe service('XblAuthManager') do
    it { should be_installed }
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

control 'windows-950' do
  title 'Ensure to disable XblGameSave service'
  desc 'This service syncs save data for Xbox Live save enabled games. If this service is stopped, game save data will not upload to or download from Xbox Live.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'microsoft': 'technet'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Microsoft', url: 'https://docs.microsoft.com/de-de/windows-server/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server'
  ref 'Github', url: 'https://github.com/MicrosoftDocs/windowsserverdocs/blob/master/WindowsServerDocs/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server.md'
  only_if('XblGameSave is not installed.') do
    service('XblGameSave').installed?
  end
  describe service('XblGameSave') do
    it { should be_installed }
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

control 'windows-952' do
  title 'Ensure to disable AppXSVC service'
  desc 'Provides infrastructure support for deploying Store applications. This service is started on demand and if disabled Store applications will not be deployed to the system, and may not function properly.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'microsoft': 'technet'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Microsoft', url: 'https://docs.microsoft.com/de-de/windows-server/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server'
  ref 'Github', url: 'https://github.com/MicrosoftDocs/windowsserverdocs/blob/master/WindowsServerDocs/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server.md'
  only_if('AppXSVC is not installed.') do
    service('AppXSVC').installed?
  end
  describe service('AppXSVC') do
    it { should be_installed }
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

control 'windows-953' do
  title 'Ensure to disable BrokerInfrastructure service'
  desc 'Windows infrastructure service that controls which background tasks can run on the system.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'microsoft': 'technet'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Microsoft', url: 'https://docs.microsoft.com/de-de/windows-server/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server'
  ref 'Github', url: 'https://github.com/MicrosoftDocs/windowsserverdocs/blob/master/WindowsServerDocs/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server.md'
  only_if('BrokerInfrastructure is not installed.') do
    service('BrokerInfrastructure').installed?
  end
  describe service('BrokerInfrastructure') do
    it { should be_installed }
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

control 'windows-954' do
  title 'Ensure to disable ClipSVC service'
  desc 'Provides infrastructure support for the Microsoft Store. This service is started on demand and if disabled applications bought using Microsoft Store will not behave correctly.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'microsoft': 'technet'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Microsoft', url: 'https://docs.microsoft.com/de-de/windows-server/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server'
  ref 'Github', url: 'https://github.com/MicrosoftDocs/windowsserverdocs/blob/master/WindowsServerDocs/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server.md'
  only_if('ClipSVC is not installed.') do
    service('ClipSVC').installed?
  end
  describe service('ClipSVC') do
    it { should be_installed }
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

control 'windows-955' do
  title 'Ensure to disable SNMPTRAP service'
  desc 'Receives trap messages generated by local or remote Simple Network Management Protocol (SNMP) agents and forwards the messages to SNMP management programs running on this computer. If this service is stopped, SNMP-based programs on this computer will not receive SNMP trap messages. If this service is disabled, any services that explicitly depend on it will fail to start.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'microsoft': 'technet'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Microsoft', url: 'https://docs.microsoft.com/de-de/windows-server/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server'
  ref 'Github', url: 'https://github.com/MicrosoftDocs/windowsserverdocs/blob/master/WindowsServerDocs/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server.md'
  only_if('SNMPTRAP is not installed.') do
    service('SNMPTRAP').installed?
  end
  describe service('SNMPTRAP') do
    it { should be_installed }
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

control 'windows-956' do
  title 'Ensure to disable OneSyncSvc service'
  desc 'This service synchronizes mail, contacts, calendar and various other user data. Mail and other applications dependent on this functionality will not work properly when this service is not running.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'microsoft': 'technet'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Microsoft', url: 'https://docs.microsoft.com/de-de/windows-server/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server'
  ref 'Github', url: 'https://github.com/MicrosoftDocs/windowsserverdocs/blob/master/WindowsServerDocs/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server.md'
  describe registry_key('OneSyncSvc', 'HKEY_LOCAL_MACHINE\\SYSTEM\CurrentControlSet\Services\OneSyncSvc') do
    it { should exist }
    it { should have_property 'Start' }
    its('Start') { should eq 4 }
  end
end

control 'windows-957' do
  title 'Ensure to disable UserDataSvc service'
  desc 'Provides apps access to structured user data, including contact info, calendars, messages, and other content. If you stop or disable this service, apps that use this data might not work correctly.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'microsoft': 'technet'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Microsoft', url: 'https://docs.microsoft.com/de-de/windows-server/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server'
  ref 'Github', url: 'https://github.com/MicrosoftDocs/windowsserverdocs/blob/master/WindowsServerDocs/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server.md'
  describe registry_key('UserDataSvc', 'HKEY_LOCAL_MACHINE\\SYSTEM\CurrentControlSet\Services\UserDataSvc') do
    it { should exist }
    it { should have_property 'Start' }
    its('Start') { should eq 4 }
  end
end

control 'windows-958' do
  title 'Ensure to disable UnistoreSvc service'
  desc 'Handles storage of structured user data, including contact info, calendars, messages, and other content. If you stop or disable this service, apps that use this data might not work correctly.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'microsoft': 'technet'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Microsoft', url: 'https://docs.microsoft.com/de-de/windows-server/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server'
  ref 'Github', url: 'https://github.com/MicrosoftDocs/windowsserverdocs/blob/master/WindowsServerDocs/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server.md'
  describe registry_key('UnistoreSvc', 'HKEY_LOCAL_MACHINE\\SYSTEM\CurrentControlSet\Services\UnistoreSvc') do
    it { should exist }
    it { should have_property 'Start' }
    its('Start') { should eq 4 }
  end
end
