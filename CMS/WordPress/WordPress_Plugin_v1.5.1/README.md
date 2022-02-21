# WordPress Plugin Perfect Survey - 1.5.1 - SQLi (Unauthenticated)
## From
* WordPress Plugin<= 1.5.1SQL Injection 
* CVE-2021-24762

## **Description:**

The Perfect Survey WordPress plugin before 1.5.2 does not validate and escape the question_id GET parameter before

using it in a SQL statement in the get_question AJAX action, allowing unauthenticated users to perform SQL injection.
