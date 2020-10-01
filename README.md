# Logrn
## binary ninja plugin for abusing logging functions
basically the same as [this plugin](https://github.com/404d/autoutils) but improved

you find a logging function which takes the current function as an argument. example:

![](https://cdn.discordapp.com/attachments/675073564508028968/760946073542983710/unknown.png)

while the logging function is selected, you run the command `rename callers to arg`

![](https://cdn.discordapp.com/attachments/675073564508028968/760946299943124992/unknown.png)

it asks you what the name of the param is which will get the function name

![](https://cdn.discordapp.com/attachments/675073564508028968/760946419254689873/unknown.png)

in this case `func_str`.
then it searches for every call of this logging function in the binary, get the parameter which holds the name of the function and renames the caller to that string. boom 2500 new symbols


# Important

Keep in mind functions you have already named will get renamed. Why? because func.auto had a huge amount of false positives in my testing leading to a huge amount of functions not getting renamed. I dont know why thats a thing.

Functions with multiple calls to the logging function will get the name of the first call. Why? because in my experience, most of the time the log function will get called multiple times with the same function name. If i were to ignore ambiguous calls, id miss a whole lot of symbols. Inlines tend to not be at the beginning of the function which is also good. Now i could check if all calls are the same but i would miss functions with inline calls that are not at the beginning of the function and a few wrongly named functions are worth that compromise imo. Just keep in mind the name is not guarenteed to be correct.

Its a background task so it wont freeze binja.

I know that when entering nothing in the prompt, there will be an exception. I dont care :p. If you do, make a pull request.
