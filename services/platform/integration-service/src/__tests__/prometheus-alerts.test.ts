import { HttpClient } from '../lib/http-client';
import { PrometheusService } from '../services/prometheus.service';
jest.mock('../lib/http-client',()=>({HttpClient:jest.fn(()=>({get:jest.fn()}))}));
let service:PrometheusService;let get:jest.Mock;
beforeEach(()=>{service=new PrometheusService();get=(HttpClient as jest.Mock).mock.results.slice(-1)[0].value.get;});
test('reads the actual nested Prometheus success envelope',async()=>{const alerts=[{labels:{alertname:'RealAlert'},state:'firing'}];get.mockResolvedValue({status:'success',data:{alerts}});expect(await service.getAlerts()).toEqual(alerts);expect(get).toHaveBeenCalledWith('/api/v1/alerts');});
test.each([null,{}, {status:'error',data:{alerts:[]}}, {status:'success',data:{alerts:{}}}])('malformed alerts never become a successful empty list: %j',async value=>{get.mockResolvedValue(value);await expect(service.getAlerts()).rejects.toThrow();});
test('provider outage propagates instead of claiming no alerts',async()=>{get.mockRejectedValue(new Error('offline'));await expect(service.getAlerts()).rejects.toThrow('offline');});
test('a confirmed empty list remains an actual empty list',async()=>{get.mockResolvedValue({status:'success',data:{alerts:[]}});expect(await service.getAlerts()).toEqual([]);});
