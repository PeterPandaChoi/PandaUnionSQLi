# PandaUnionSQLi 
<br/>'Panda Union SQL injection' (or 'PandaUnionSQLi') is a rudimentary tool for automating 'Union SQL injection' pentest Process, currently specialized in blind SQLi, Coded fully in Python, with a few lib.
<br/>'Panda Union SQLi'는 Union SQL injection의 침투테스트를 위한 초보적인 툴이며, 몇몇 라이브러리를 포함한 파이썬으로 코딩하였습니다.
<br/>해당 코드의 첫 커밋은 블로그에 상술되어 있습니다. [https://blog.naver.com/panda_university/223281163940]

# Specification
<br/>Method : get
<br/>param : search
<br/>

# Required library 필요한 라이브러리
1. requests                **[required for sending requests to web]**
2. parse                   [possibly already installed, but just in case]
3. diff_match_patch        **[used for checking differences between two requests]**
4. bs4 (or BeautifulSoap)  **[used for stripping html tags and etcs]**
5. lxml                    [you need this to use bs4]

~~~
pip install requests
pip install parse
pip install diff_match_patch
pip install bs4
pip install lxml
~~~

# Basic Process
This Union SQL Injection goes through 7 steps.
1. Find SQLi point [ input : Links and Param ]
2. Count Column used in select phrase, by using "order by" payload.
3. Finding holes(spot where you can see the result of query) 
4. DB Name, by using "Database()" payload. [ you may need to choose which hole to show result ]
5. Table Name, by checking schema [ you need to choose which item is the name of a table ]
6. Column Name, by checking schema [ you need to choose which item is the name of a column ]
7. Row Name [ you need to choose which item is the name of a row ]

# Future Plan
1. get/post
2. order by - bin Search Algorithm (2b more quiet)
3. parameter Customize
4. code cleaning
5. multiple table,column







