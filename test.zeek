@load base/frameworks/sumstats
global my_count = 0;
event zeek_init()
    {
    local r1 = SumStats::Reducer($stream="404.lookup", $apply=set(SumStats::UNIQUE));
    SumStats::create([$name="404.replys.unique",
                      $epoch=10mins,
                      $reducers=set(r1),
                      $epoch_result(ts: time, key: SumStats::Key, result: SumStats::Result) =
                        {
                        local r = result["404.lookup"];
                        if( r$num > 2 && r$num/my_count > 0.2 && r$unique/r$num >0.5 )
                        	print fmt("%s is a scanner with %d scan attempts on %d urls.", 
                        				key$host, r$num, r$unique);
                        }]);
    }

event http_reply(c: connection, version:string, code:count, reason:string)
    {
    ++my_count;
    if ( c$http$status_code==404 )
        SumStats::observe("404.lookup", [$host=c$id$orig_h], [$str=c$http$uri]);
    }
