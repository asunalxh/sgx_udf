-- create table Ciphertext(
--     id varchar(128),
--     P_BRAND varchar(128);
-- );

-- create function myinit returns string soname 'app.so';
-- create function myinsert returns string soname 'app.so';
-- create function mysearch returns string soname 'app.so';
-- create function mydel returns string soname 'app.so';
-- create function readdata returns string soname 'app.so';
-- create function getval returns string soname 'app.so';

delimiter //
create procedure run_add_data(in filedir varchar(128))
begin
    declare i int default 0;
    declare start_time int;
    declare end_time int;
    declare id varchar(256);
    declare val varchar(256);
    declare encode varchar(256);
    declare temp varchar(256);
    declare ans int;

    set start_time = unix_timestamp(now());

    -- 读取需要添加的数据文件
    set temp = readdata(filedir);
    set temp = myinit();
    set i = 0;
    while (i < 2000)
        do
            set id = getval(i, 0);
            set val = getval(i, 1);
            set encode = myinsert(id, val);

            insert into Ciphertext values (id, encode);

            set i = i + 1;
        end while;

    set end_time = unix_timestamp(now());
    set ans = end_time - start_time;
    select ans;
end;//

delimiter //
create procedure run_del_data()
begin
    declare i int default 0;
    declare start_time int;
    declare end_time int;
    declare temp varchar(128);
    declare mid varchar(128);
    declare ans int;

    set start_time = unix_timestamp(now());

    -- 读取需要删除的id文件（一列id即可）
    set temp = readdata("/home/asunalxh/VSCode/sgx_udf/PART.csv") ;

    set i = 0;
    while (i < 500) do
        set mid = getval(i,0);
        set temp = mydel(mid);

        delete from Ciphertext where id = mid;

        set i = i + 1;
        end while;

    set end_time = unix_timestamp(now());
    set ans = end_time - start_time;
    select ans;
end;//

-- delimiter //
-- create procedure run_search()
-- begin
--     declare i int default 0;
--     declare start_time int;
--     declare end_time int;
--     declare val varchar(128);
--     declare temp varchar(128);
--     declare ans int;

--     set start_time = unix_timestamp(now());

--     -- 读取需要搜索的key的文件（一列关键字即可）
--     set temp = readdata("/home/asunalxh/VSCode/sgx_udf/PART.csv") ;

--     set i = 0;
--     while (i < 500) do
--         set mkey = getval(i,0);

--         set temp = select mysearch(mkey);
        
--         set i = i + 1; 
--         end while;
    
--     set end_time = unix_timestamp(now());
--     set ans = end_time - start_time;
--     select ans;
-- end;//


