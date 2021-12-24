-- -- create table Ciphertext(
-- --     id varchar(128),
-- --     P_BRAND varchar(128);
-- -- );

-- create function myinit returns string soname 'app.so';
-- create function myinsert returns string soname 'app.so';
-- create function mysearch returns string soname 'app.so';
-- create function mydel returns string soname 'app.so';
-- create function readdata returns string soname 'app.so';
-- create function getval returns string soname 'app.so';

-- select myinit();

-- -- 读取需要添加的数据文件
-- select readdata("/home/asunalxh/VSCode/sgx_udf/PART.csv");

-- declare i int;
-- declare id varchar(128);
-- declare val varchar(128);
-- declare start_time int;
-- declare end_time int;

-- -- 插入操作
-- set start_time = select unix_timestamp(now());
-- set i=1;
-- while i < 100
-- begin
--     id=getid(i);
--     val=getvalue(i);
--     insert into Ciphertext values(id,myinsert(id,val));
--     i = i +1;
-- end


-- -- 读取需要删除的数据文件
-- select readdata("/home/asunalxh/VSCode/sgx_udf/PART.csv");
-- -- 删除操作
-- set i=1
-- while i < 10
-- begin
--     id=getid(i);
--     delete from Ciphertext where id = mydel(id);
--     i = i +1;
-- end


