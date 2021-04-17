@load base/frameworks/sumstats
event zeek_init()
    {
    local r1 = SumStats::Reducer($stream="response.lookup", $apply=set(SumStats::SUM));
    local r2 = SumStats::Reducer($stream="404.lookup", $apply=set(SumStats::SUM));
    local r3 = SumStats::Reducer($stream="url.lookup", $apply=set(SumStats::UNIQUE));
    SumStats::create([$name="404.replys.unique",
                      $epoch=10mins,
                      $reducers=set(r1, r2, r3),
                      $epoch_result(ts: time, key: SumStats::Key, result: SumStats::Result) =
                        {
                        local R1 = result["response.lookup"];
                        local R2 = result["404.lookup"];
                        local R3 = result["url.lookup"];
                        if ( R2$sum > 2 )
                        	if ( R2$sum/R1$sum > 0.2 )
                        		if ( R3$unique/R2$sum > 0.5 )
                        			print fmt(" %s is a scanner with %d scan attempts on %d urls", key$host, R2$sum, R3$unique);
                        	
                        }]);
    }

event http_reply(c: connection, version:string, code:count, reason:string)
    {
    SumStats::observe("response.lookup", [$host=c$id$orig_h], [$num=1]);
    if ( c$http$status_code==404 )
    	SumStats::observe("404.lookup", [$host=c$id$orig_h], [$num=1]);
        SumStats::observe("url.lookup", [$host=c$id$orig_h], [$str=c$http$host + c$http$uri]);
    }
