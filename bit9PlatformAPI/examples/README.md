## **Introduction**

This document is intended for programmers who want to write code to interact with Bit9 Platform using custom scripts or from other applications. Bit9 API is a RESTful API that can be consumed over HTTPS protocol using any language that can create get URI requests and post/put JSON requests as well as interpret JSON responses.
By accessing and/or using the API and Documentation provided on this site, you hereby agree to the following terms:

### **Disclaimer**
 
You may access and use the API and Documentation only for your own internal business purposes and in connection with your authorized use of Bit9 software.  
 
Title to the API and the Documentation, and all intellectual property rights applicable thereto, shall at all times remain solely and exclusively with Bit9 and Bit9�s licensors, and you shall not take any action inconsistent with such title.
 
THE API AND RELATED DOCUMENTATION ARE PROVIDED �AS IS� WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR IMPLIED.
 
IN NO EVENT SHALL BIT9 BE LIABLE FOR SPECIAL, INCIDENTAL, CONSEQUENTIAL, EXEMPLARY OR OTHER INDIRECT DAMAGES OR FOR DIRECT DAMAGES ARISING OUT OF OR RESULTING FROM YOUR ACCESS OR USE OF THE API AND DOCUMENTATION, EVEN IF BIT9 IS ADVISED OF OR AWARE OF THE POSSIBILITY OF SUCH DAMAGES. 

### **Versioning**

Current version of Bit9 API is v1. All API calls are based in address https://<your server name>/api/bit9platform/v1

### **Authentication**

Bit9 APIs are authenticated through the API token. This token has to be placed inside each HTTP request's 'X-Auth-Token' header. API token is tied to the console user. To obtain the API token, ask Bit9 Server administrator to generate special user and token for you. Best practice is to have separate console user with minimum required access controls for each API client.

### **Access Controls**

API client has same access level as its corresponding console user. For example, in order to get access to the 'event' object, user associated with API token will need permission to view events. Required permissions are listed with each API in this document. If caller lacks required privileges, HTTP error 401 - Unauthorized will be returned.

### **Responses**

Successful calls will return either HTTP 200 - OK or HTTP 201 - Created, depending if request created a new object or just modified/deleted existing one.   
In case of POST and PUT, response will contain body of the modified or created object in the content, and also URI of created or modified object in url property of the response.  
In case of GET, response will contain body of the searched object(s) in the content.  
Failed calls will return errors in range 400-599, most often:   
HTTP 400 - Bad request - Usually means that request contains unexpected parameters. More details about error can be found in the response content.  
HTTP 401 - Unauthorized - Either authentication (invalid token) or access control (missing RBAC) error.  
HTTP 403 - Forbidden - Specified object cannot be accessed or changed.  
HTTP 404 - Not found - Object referenced in the request cannot be found.  
HTTP 503 - Service unavailable - Cannot return object at this moment because service is unavailable. This can happen if too many file downloads are happening at the same time. You can try later.

### **Searching**

Searching is done through the GET request, by passing search elements as URL query parts:  
v1/computer?q=_<query condition 1>_&q=_<query condition 1>_...&group=_<optional group term>_&sort=_<optional sort term>_&offset=_<optional offset>_&offset=_<optional limit>_  
Following sections describe these query parts.

#### **Query Condition**

Multiple conditions can be added, and each has to be satisfied for the result set.  
Individual condition can have one or multiple subconditions, separated with '|' (pipe) symbol Condition contains three parts: name, operator and value.

- Name is any valid field in the object that is being queried&nbsp;
- Operator is any of valid operators (see below). All operators consist of a single character&nbsp;
- Value is compared with operator and depends on field type.&nbsp;

Possible operators are:

- : results in LIKE comparison for strings, and = comparisons for other types. Note that LIKE comparison for strings results in '=' comparison if string doesn't contain wildchars. String comparison is case insensitive.&nbsp;
- ! results in NOT LIKE comparison for strings, and <> comparison for other types. Note that NOT LIKE comparison for strings results in '<>' comparison if string doesn't contain wildchars. String comparison is case insensitive. &nbsp;
- < Less then - can be used for both strings and numerical values &nbsp;
- > Greater then - can be used for both strings and numerical values &nbsp;
- + logical AND operation (valid only for numerical values). True if value has all bits as in operand. This can be used to check existence of given flag in a field &nbsp;
- - logical NAND operation (valid only for numerical values). True if value has none of the bits in the operand. This can be used to check non-existence of given flag in a field &nbsp;
- | separating values with | (pipe) symbol will cause both values ot be included in the condition. Example "q=fileName:test1.exe|test2.exe" will match all objects where filename is either test1.exe or test2.exe. Note that negative conditions (- and !) will exclude entries that match either of included values. &nbsp;

Example of valid filter segment:

##### Request:

[GET] https://myServer/api/bit9platform/v1/Computer?q=ipAddress:fe00\*|ff00\*&q=computerTag!&q=dateCreated>-10h

##### Resulting SQL query condition evaluated:

... WHERE (ipAddress LIKE 'fe00%' OR ipAddress LIKE 'ff00%')

&nbsp; &nbsp; AND computerTag NOT LIKE ''

&nbsp; &nbsp; AND dateCreated>DATEADD(HOUR,-10, GETUTCDATE())

Note: All string matching will be case insensitive

#### **Limiting Results and Getting Result Count**

Attributes: &offset=x&limit=y, where x is offset in data set, and y is maximum number of results to retrieve

Special values for limit are 0 and -1:

- If not specified: First 1000 results will be returned.
- If set to -1: Only result count will be returned, without actual results. Offset parameter is ignored in this case.
- If set to 0: All results will be returned. Offset parameter is ignored in this case. 
  Note that some result sets could be very large, resulting in query timeout. Therefore, unless you know that query will not return more than 1000 results, it is recommended to retrieve data in chunks using offset and limit.

  
Here is example on how to get result count from a query:

##### Request:

[GET] https://myServer/api/bit9platform/computer?limit=-1

##### Response:

{"count":1284}

#### **Sorting**

Sorting is optional and can be defined with a single attribute: _&sort=xyz [ASC|DESC]_

- There can be only one sorting field&nbsp;
- Default sort order (if omitted) is ASC&nbsp;
- xyz is field name from the result set&nbsp;

#### **Grouping**

Grouping is optional and can be defined with a single attribute: _&group=xyz_

- There can be only one grouping field&nbsp;
- When grouping is specified, sorting is ignored � output is automatically sorted by grouping field&nbsp;

Output of grouping is always array of objects with value and count fields. "Value" is group field value, and "count" is number of rows that have that name for the grouped field. Here is example:

##### Request:

[GET] https://myServer/api/bit9platform/v1/Computer?group=osShortName

##### Response:

[

&nbsp; &nbsp; {"value":"CentOS 5","count":53},

&nbsp; &nbsp; {"value":"CentOS 6","count":826},

&nbsp; &nbsp; {"value":"Mac","count":2311},

&nbsp; &nbsp; {"value":"Windows 7","count":1330}

]

&nbsp;

