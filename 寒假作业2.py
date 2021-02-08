# Author：Hugh
# -*- codeing = utf-8 -*-
# @Time : 2021/2/4 15:17
# @Author : Hugh
# @File : 寒假作业2.py
# @Software: PyCharm
from scapy.all import *
import re

from flask import Flask
from jinja2 import Markup
from pyecharts import options as opts
from pyecharts.charts import Bar,Grid,Pie,Line


control_time = 25
Φ = 50000  #包数
φ = 100000  #包长
#timeout参数用来控制抓包的周期
packet =sniff(timeout=control_time,prn=lambda x : x.sprintf("{IP:%IP.src%-> %IP.dst%}"))
p=wrpcap('packet.pcap', packet)
packets=rdpcap("packet.pcap")


cnt_udp = 0
cnt_tcp = 0
cnt_arp = 0
cnt_icmp = 0
cnt_igmp = 0
cnt_ospf = 0
cnt_other = 0

#
cnt_len = 0
cnt_bags = 0
cnt_success_bags = 0

five_tuple = {}
change_len_cnt = {}
# 五元组提取区
for bag in packets:
    cnt_bags = cnt_bags + 1
    print("这是第{}个包".format(cnt_bags))

    try:
        if (bag[1].proto == 6 or bag[1].proto == 17):
            PROTO = bag[1].proto
            Len= bag[1].len
            cnt_success_bags=cnt_success_bags+1
            cnt_len=cnt_len+Len
            change_len_cnt[cnt_success_bags] = cnt_len


            if (PROTO == 17):
                Proto = "UDP"
                cnt_udp = cnt_udp + 1
            else:
                Proto = "TCP"
                cnt_tcp = cnt_tcp + 1
            Src = bag[1].src
            Dst = bag[1].dst
            Sport = bag[1].sport
            Dport = bag[1].dport

            s = "{:}  \n Src : {}:{}\n   Dst : {}:{} \n Len : {}".format(Proto, Src, Sport, Dst, Dport, Len)
            if s not in five_tuple:
                five_tuple[s] = [0,Len]
            else:
                five_tuple[s][0] = five_tuple[s][0] + 1
                five_tuple[s][1] = five_tuple[s][1] + Len
        else:
            if(bag[1].proto == 1):
                 cnt_icmp = cnt_icmp + 1
            elif(bag[1].proto == 2):
                 cnt_igmp = cnt_igmp + 1
            elif(bag[1].proto == 89):
                 cnt_ospf = cnt_ospf + 1
    except Exception as  e:
        try:
            if (bag[0].type == 2054):
                cnt_arp = cnt_arp + 1
            else:
                cnt_other = cnt_other + 1
        except Exception as e:
            cnt_other = cnt_other + 1

        # print(Five_Tuple)
# 协议：其中1，标识ICMP、2标识IGMP、6标识TCP、17标识UDP、89标识OSPF。
# data.payload.name:'IP','IPV6','ARP'或者其他
print(change_len_cnt)

#绘图材料准备区
#1.柱状图区
##正则
#s = "{}  {}:{}   {}:{}".format(Proto, Src, Sport, Dst, Dport)
#pattern = re.compile(r'.*?([1-9][0-9]{0,2}.[1-9][0-9]{0,2}.[1-9][0-9]{0,2}.[1-9][0-9]{0,2}).*?')   # re.I 表示忽略大小写
def Creating_Bar_Source(Five_Tuple):
    xaxis = []
    yaxis = []
    for x,y in Five_Tuple.items():

        if y[0] > Φ or y[1] > φ:                 ##设置阈值
          #xsrc=pattern.match(x)
          #xaxis.append(xsrc.group(1))
          xaxis.append(x)
          yaxis.append(y[0])
    print(xaxis)
    print(yaxis)
    return xaxis,yaxis
#2.小bar图区
xaxis_small=['Φ','φ']
yaxis_small=[Φ,φ]
#3.玫瑰饼图区
proto_types=["UDP","TCP","ARP","ICMP","IGMP","OSPF","Other"]
proto_nums=[cnt_udp,cnt_tcp,cnt_arp,cnt_icmp,cnt_igmp,cnt_ospf,cnt_other]
zipped=zip(proto_types,proto_nums)
#4.折线区域
len_x = []
len_y = []
for lenx,leny in change_len_cnt.items():
    len_x.append(lenx)
    len_y.append(leny)

# 绘图区
app = Flask(__name__, static_folder="templates")
def grid_base() -> Grid():
  xaxis,yaxis =Creating_Bar_Source(five_tuple)

  bar_five = (
      Bar(init_opts=opts.InitOpts(width='60px', height='180px'))
          .add_xaxis(xaxis)
          .add_yaxis("count_five", yaxis)
          .set_global_opts(
                  title_opts=opts.TitleOpts(title="Flow_detector", subtitle="Suspicious_address",pos_top="1%",pos_left="1%"),
                  legend_opts=opts.LegendOpts(pos_top="6%",pos_left="1%"),
                  xaxis_opts=opts.AxisOpts(name="five_tuple"),
                  yaxis_opts=opts.AxisOpts(name="five_tuple_num")
      )
          .set_series_opts(label_opts=opts.LabelOpts(is_show= True))

  )
  bar_threshold = (
      Bar(init_opts=opts.InitOpts(width='30px', height='60px'))
          .add_xaxis(xaxis_small)
          .add_yaxis("count_threshold", yaxis_small)
          .set_global_opts(
               title_opts=opts.TitleOpts(title="Threshhold_value",pos_top="3%", pos_bottom='80%', pos_left='75%',pos_right="10%"),
               legend_opts=opts.LegendOpts(pos_top="7%", pos_bottom='80%', pos_left='75%',pos_right="10%"))

  )
  pie = (
         Pie(init_opts=opts.InitOpts(width="600px",height="300px"))#,is_label_show=True
         .add("", [list(z) for z in zipped],rosetype=True,radius=[40,90],center=["17%","80%"])
        # .set_colors(["blue", "green", "yellow", "pink"])
         .set_global_opts(title_opts=opts.TitleOpts(
             title="Proto_percent",pos_top="50%",pos_bottom="60%",pos_left="1%"),
             legend_opts=opts.LegendOpts(pos_left="1%",pos_top="55%"))
         .set_series_opts(label_opts=opts.LabelOpts(formatter="{b}: {c}"))
  )

  line = (
    Line()
    .add_xaxis(len_x)
    .add_yaxis("DOT", len_y, is_connect_nones=True)
    .set_global_opts(
        title_opts=opts.TitleOpts(title="Connection_length_count", pos_top="50%", pos_left='50%'),
        legend_opts=opts.LegendOpts(pos_top="55%",pos_left="52%"),
        xaxis_opts=opts.AxisOpts(name="total_bag_count"),
        yaxis_opts=opts.AxisOpts(name="total_bag_length")
                    )
    .set_series_opts(label_opts=opts.LabelOpts(is_show=False))
  )
  grid = (
      Grid(init_opts=opts.InitOpts(width='1400px',height='1000px',bg_color="#f7b733"))
          #.width("900px")
          .add(bar_five, grid_opts=opts.GridOpts(pos_top="11%",pos_bottom='60%',pos_right="25%"))
          .add(bar_threshold, grid_opts=opts.GridOpts(pos_top="10%", pos_bottom='80%', pos_left='80%',pos_right="10%"))
          .add(line, grid_opts=opts.GridOpts(pos_top="60%",pos_bottom="10%",pos_left="50%"))
          .add(pie, grid_opts=opts.GridOpts(pos_bottom="10%",pos_left="10%",pos_top="85%",pos_right="90%"))
  )
  return grid
@app.route("/")
def index():
  c = grid_base()
  return Markup(c.render_embed())


#控制中心
if __name__ == "__main__":
  app.run(port=60)