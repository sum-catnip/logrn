# Logrn
## binary ninja plugin for abusing logging functions

you find a logging function which takes the current function as an argument example:
![](https://cdn.discordapp.com/attachments/675073564508028968/760946073542983710/unknown.png)
while the logging function is selected, you the command `rename callers to arg`
![](https://cdn.discordapp.com/attachments/675073564508028968/760946299943124992/unknown.png)
it asks you what the name of the param is which will get the function name
![](https://cdn.discordapp.com/attachments/675073564508028968/760946419254689873/unknown.png)
in this case `func_str`
then it searches for every call of this logging function in the binary get the parameter which holds the name of the function and renames the caller to that string. boom 2500 new symbols
