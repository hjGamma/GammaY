# <font style="color:rgb(31, 35, 40);">Stalker——Web Application Scanner.</font>
![](https://cdn.nlark.com/yuque/0/2025/png/281716/1741571418765-47ae18b4-8039-41a0-948a-656366a2c4f9.png)

<font style="color:rgb(31, 35, 40);">  
</font><font style="color:rgb(31, 35, 40);">Stalker</font><font style="color:rgb(31, 35, 40);"> is a Go-based web application scanner. It integrates the advantages of flexibility, scalability, and comprehensiveness.</font>

## <font style="color:rgb(31, 35, 40);">Installation</font>
<font style="color:rgb(31, 35, 40);">If you have a Go environment, make sure you have Go >= 1.20 with Go Modules enable and run the following command.</font>

:::tips
<font style="color:rgb(31, 35, 40);">go install github.com/hjGamma/GammaY@latest</font>

:::

<font style="color:rgb(31, 35, 40);">Please visit the Official Documention for more details.</font>

## <font style="color:rgb(31, 35, 40);">Usage</font>
<font style="color:rgb(31, 35, 40);">Stalker</font><font style="color:rgb(31, 35, 40);"> [flags] gammay [command]</font>

<font style="color:rgb(31, 35, 40);">Command contains nmap, subdomain detection, sqlmap, xss, Poc,version... </font>

<font style="color:rgb(31, 35, 40);">The tool defines different commands, each with its own flag. The -t in the flag is a required input variable.</font>

<font style="color:rgb(31, 35, 40);">You can see the flags contained under different commands by entering the following command</font>

<font style="color:rgb(31, 35, 40);">Stalker [command] -h || Stalker -h || Stalker nmap -h</font>





## Mudole
### Nmap
#### Nmap Usage
![](https://cdn.nlark.com/yuque/0/2025/png/281716/1741572209870-58b1e282-a95f-4fbc-bf75-055045b96556.png)



1. FingerPrinting

![画板](https://cdn.nlark.com/yuque/0/2025/jpeg/281716/1741334910271-2f772321-a957-4273-8e2c-a28e59405f31.jpeg)

![](https://cdn.nlark.com/yuque/0/2025/png/281716/1741572706316-11edefbc-cb66-4dd3-bc80-ab80fd872ed7.png)

2. subdomain detection

![](https://cdn.nlark.com/yuque/0/2025/png/281716/1741573046755-18d26afe-1a80-496e-a246-308a8d9e57e2.png)

3. Layer Exploit

There are two types of directory blasting modules in this tool. One type gives high weight when a valid path is found by weight assignment and autonomous construction, and deep blasting can be performed for high weight paths. And the autonomous splicing catalog variant is designed.



![](https://cdn.nlark.com/yuque/0/2025/png/281716/1741573406843-df65e94b-e3f9-448d-861b-2f16be8c01d7.png)



![](https://cdn.nlark.com/yuque/0/2025/png/281716/1741573704568-e1d45ed1-8b75-4303-87f3-a374041b5473.png)

