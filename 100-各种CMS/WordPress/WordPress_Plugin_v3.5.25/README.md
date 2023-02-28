# WordPress Plugin WP User Frontend 3.5.25 - SQLi (Authenticated)
## From
* WordPress Plugin<= 3.5.25 SQL Injection 
* CVE: CVE-2021-25076

### Description

The WP User Frontend WordPress plugin before 3.5.26 does not validate and escape the status parameter

before using it in a SQL statement in the Subscribers dashboard, leading to an SQL injection.

Due to the lack of sanitisation and escaping, this could also lead to Reflected Cross-Site Scripting
