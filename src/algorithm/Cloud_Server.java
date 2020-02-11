/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package algorithm;

import java.security.SecureRandom;

/**
 *
 * @author NAVID_Home
 */
public class Cloud_Server {
    
    
    byte BS_m [];
    String SID_m;
    byte d [] = new byte[16];
    
    
    public void cloud_server_register( String SID_m )
    {
        this.SID_m = SID_m;
        SecureRandom random = new SecureRandom();
        byte d[] = new byte[16]; // 128 bits are converted to 16 bytes;
        random.nextBytes(d);     // create 128 bit random number and store it in d
        this.d = d;
        BS_m = Algorithm.Control_Server.csr(d , SID_m);
    }
    
    
    
    public byte[][] authentication(byte[] Gi, byte[] Fi, byte[] Zi, byte[] PIDi, byte[]TSi) throws Exception
    {
        byte[] TSm = Algorithm.get_timestamp();
        if((Algorithm.byteArrayToInt(TSm)-Algorithm.byteArrayToInt(TSi)) >  1000)           // Delta t
        {
            throw new Exception("user cloud_server time_out");                              //TSm - TSi > delta t
        }
        
        byte[] Nm = new byte[16];
        SecureRandom random = new SecureRandom();
        random.nextBytes(Nm);                                               // create 128 bit random number
        byte[] Ji = Algorithm.xor(BS_m, Nm);                                // Ji = BSm xor Nm
        byte[] TSj = Algorithm.get_timestamp();                             // TSj TODO ??? 
        byte[] Ki = Algorithm.hash(Algorithm.concat(BS_m, Algorithm.concat(Nm, Algorithm.concat(Gi, TSm))));        // Ki = h(Nm || BSm || Gi || TSj)
                                                                                        // PROBLEM
        
        byte[] PSIDm_PROBLEM = Algorithm.hash(Algorithm.concat(SID_m.getBytes(), d));                           /////////////////////////// PROBLEM
        
        
        byte[][] values=new byte[4][];
        try {
            values = Algorithm.Control_Server.authentication(Ji, Ki, PSIDm_PROBLEM, Gi, Fi, Zi, PIDi, TSi, TSm);  ///////////////////////// PROBLEM
        } catch (Exception e) {
            throw e;
        }
        
        byte[] Pcs = values[0];
        byte[] Rcs = values[1];
        byte[] Qcs = values[2];
        byte[] Vcs = values[3];
        
        byte[] Wm = Algorithm.hash(Algorithm.concat(BS_m, Nm));                 // Wm = h(BSm || Nm)  
        byte[] Ni_xor_Ncs = Algorithm.xor(Rcs, Wm);                             // Ni xor Ncs = Rcs xor Wm
        byte[] SKm = Algorithm.hash(Algorithm.xor(Ni_xor_Ncs, Nm));             // SKm = h(Ni xor Ncs xor Nm)
        byte[] Vcs_star = Algorithm.hash(Algorithm.concat(Ni_xor_Ncs, SKm));    // Vcs* = h((Ni xor Ncs) || SKm)
        
        if (!(Algorithm.are_equal(Vcs_star, Vcs)))
        {
            throw new Exception("Vcs* != Vcs");
        }
        
        byte[][] result = new byte[2][];
        result[0]=Pcs;
        result[1]=Qcs;
        
        return result; 
    }
}
