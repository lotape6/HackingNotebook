Challenge: https://ringzer0ctf.com/challenges/164

# First look
We observe that as we unzip the attached file we've got a web server's log file. Likely it is a Apache server or similar. We start checking the different petitions being made and easily we observe that there are some strange payloads hidden in the petitions to `backednd.php` page, specially trying to bypass the `admin` user.

```
admin%27%20AND%20IF%28/%2AIlPNSD1%2A/SUBSTRING%28REVERSE%28/%2A0zS7LBwEN%2A/CONV%28HEX%28SUBSTRING%28/%2A9ZCMRCCd9%2A/%28SELECT%20database%28%29%29%2C1%2C1%29%29%2C16%2C2%29%29/%2AZaoJyioC8p%2A/%2C2%2C1%29%3D1%2CSLEEP%282%29%2C98647132%29%20AND%20%2742

admin' AND IF(/*IlPNSD1*/SUBSTRING(REVERSE(/*0zS7LBwEN*/CONV(HEX(SUBSTRING(/*9ZCMRCCd9*/(SELECT database()),1,1)),16,2))/*9ZCMRCCd9*/,2,1)=1,SLEEP(2),98647132) AND '42
```

We can easily observe that the attacker is checking multiple users by entering some kind of ID or cookie related to them in the early access. As we can observe, the response size of each individual GET is different, so we shall suppose that the attacker is accessing to different users' info. 


Later on we see how they try to access the following table and schema:
```
10.0.1.1 - - [01/Mar/2015:13:14:45 -0500] "GET /backend.php?user=admin' AND IF(/*iC*/SUBSTRING(REVERSE(/*dzzYaxYMNEJ*/CONV(HEX(SUBSTRING(/*bgv9*/(SELECT GROUP_CONCAT(column_name) FROM information_schema.columns WHERE TABLE_SCHEMA = 0x63686172745f6462 AND TABLE_NAME = 0x666c6167/*EGi*/),5,1)),16,2))/*wpDrzIP*/,1,1)=1,SLEEP(2),777525694) AND


0x63686172745f6462 -> chart_db
0x666c6167 -> flag
```

It definitelly looks like it's using sqlmap and some sort of timed way to extract the flag. After filtering a little bit the logs and removing unnecessary logs (the ones not starting by `admin'`) we observe how it's using the conversion from hex to binary of some SQL queries and extracting one single bit to later on sleep during 2 seconds depending on the bit value. So, bit to bit the queries shows the names of the database:

0x63686172745f6462 ->  chart_db

Then it obtains the tables 

0x666c6167 -> flag

And the name of the column -> flag 

Ending with the reception of the flag with the following queries

```
[01/Mar/2015:13:15:03] "GET /backend.php?user=admin' AND IF(SUBSTRING(REVERSE(CONV(HEX(SUBSTRING((SELECT GROUP_CONCAT(CONCAT(flag)) FROM chart_db.flag),1,1)),16,2)),1,1)=1,SLEEP(2),3724) AND '16173 HTTP/1.1" 200 431
```

After some manual clean up of the information in all the logs related to the flag extraction, I've came up with a CSV where each row contains the timestamp (mm:ss) of the petition (since the rest of the timestamp is constant), then the offset of the character being retieved and the third and last column is the offset of the bit being obtained. Example of the first entries above:

```
15:03,1,1
15:03,1,2
15:05,1,3
15:07,1,4
15:07,1,5
15:07,1,6
15:07,1,7
15:09,2,1
15:09,2,2
15:09,2,3
15:11,2,4
15:13,2,5

...
```

Then, I've created a simple python script where we automatically reconstruct each character by checking the timestamps of the current petition and the next one. If the offset is equal (or greater) than 2, then we know that the bit of the position given by the third column is a 1, otherwise it is 0. We have initially constructed a list of zeros with the length equal to the num of chars (maximum value of the second column -> 38) and then we populate each bit according to the logs of the execution of the database.

Finally we are able to reconstruct the flag:

```
Raw flag
[70, 76, 65, 71, 45, 111, 122, 53 ...]
The flag decoded is -> FLAG-oz...
```