#[macro_use]
extern crate log;
mod utils { pub use public::bytes; }
mod common {
    mod consts { pub use public::consts::*; }
    pub use public::enums;
    #[path = "/root/yb/git/TrafLens/.traflens/work/decapsulate-review/actual-decapsulate-prefix.rs"]
    pub mod decapsulate;
}
use common::decapsulate::{TunnelInfo,TunnelType,TunnelTypeBitmap};
fn eth()->Vec<u8>{vec![2,0,0,0,0,1,2,0,0,0,0,2,8,0]}
fn ip4(ihl:usize,protocol:u8,payload:&[u8])->Vec<u8>{
 let mut frame=eth();let mut ip=vec![0;ihl];ip[0]=0x40|(ihl/4)as u8;ip[2..4].copy_from_slice(&((ihl+payload.len())as u16).to_be_bytes());ip[8]=64;ip[9]=protocol;ip[12..20].copy_from_slice(&[10,1,2,3,10,4,5,6]);frame.extend(ip);frame.extend_from_slice(payload);frame
}
fn vxlan()->Vec<u8>{let mut tunnel=vec![8,0,0,0,0x12,0x34,0x56,0];tunnel.extend(eth());let mut udp=vec![0x9c,0x40,0x12,0xb5];udp.extend_from_slice(&((8+tunnel.len())as u16).to_be_bytes());udp.extend_from_slice(&[0,0]);udp.extend(tunnel);ip4(24,17,&udp)}
fn run(name:&str,mut frame:Vec<u8>){let before=frame.clone();let mut info=TunnelInfo::default();let mask=TunnelTypeBitmap::new(&vec![TunnelType::Vxlan,TunnelType::Ipip]);let offset=info.decapsulate(&mut frame,14,&mask);println!("{name}: offset={offset}, mutated={}, tier={}, type={:?}",before!=frame,info.tier,info.tunnel_type);}
fn main(){
 let valid=vxlan();run("control_valid_vxlan",valid.clone());
 let mut udp_bad=valid.clone();udp_bad[42..44].copy_from_slice(&65535u16.to_be_bytes());run("UDP65535_exceeds_outer_IP54",udp_bad);
 let mut option_bad=valid.clone();option_bad[34..38].copy_from_slice(&[0x82,1,0,0]);run("IPv4_option_length1",option_bad);
 let mut short=valid.clone();short[16..18].copy_from_slice(&23u16.to_be_bytes());run("control_short_declared_IP",short);
 let mut short_udp=valid.clone();short_udp[42..44].copy_from_slice(&7u16.to_be_bytes());run("control_short_declared_UDP",short_udp);
 let mut inner=ip4(20,1,&[])[14..].to_vec();inner[2..4].copy_from_slice(&500u16.to_be_bytes());let mut ipip=ip4(20,4,&inner);ipip.extend_from_slice(&[0x5a;500]);run("IPIP_inner500_exceeds_outer_payload20_with_padding",ipip);
 let mut snap=vxlan();snap[16..18].copy_from_slice(&1024u16.to_be_bytes());snap[42..44].copy_from_slice(&1000u16.to_be_bytes());run("control_valid_snaplen_udp",snap);
 let mut inner=ip4(20,1,&[])[14..].to_vec();inner[2..4].copy_from_slice(&500u16.to_be_bytes());let mut snap=ip4(20,4,&inner);snap[16..18].copy_from_slice(&520u16.to_be_bytes());run("control_valid_snaplen_ipip_v4",snap);
 let mut inner6=vec![0;40];inner6[0]=0x60;inner6[4..6].copy_from_slice(&500u16.to_be_bytes());let mut invalid6=ip4(20,41,&inner6);invalid6.extend_from_slice(&[0x55;500]);run("IPIP_inner_v6_540_exceeds_outer_payload40",invalid6);
 let mut snap6=ip4(20,41,&inner6);snap6[16..18].copy_from_slice(&560u16.to_be_bytes());run("control_valid_snaplen_ipip_v6",snap6);

}
