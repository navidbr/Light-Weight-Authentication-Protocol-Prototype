/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package algorithm;

import static algorithm.Algorithm.print;
import static algorithm.Algorithm.xor;
import java.security.SecureRandom;
import java.util.Scanner;

/**
 *
 * @author NAVID_Home
 */
public class User {
    String ID_i="";
    Smart_Card smart_card = new Smart_Card();
    public void user_register( String ID_i , String P_i )
    {
        this.ID_i = ID_i;
        byte b1 []= new byte[16];
        byte b2 []= new byte[16];
        byte Ai [];
        byte PID_i [];
        byte bb_i [];
        SecureRandom random = new SecureRandom();
        random.nextBytes(b1);     // create 128 bit random number
        random.nextBytes(b2);     // create 128 bit random number
        Ai = Algorithm.hash(Algorithm.concat(P_i.getBytes(), b1));
        PID_i = Algorithm.hash(Algorithm.concat(ID_i.getBytes(), b2));
        bb_i = Algorithm.xor(b2, Ai);
        smart_card = Algorithm.Control_Server.ur(Ai, PID_i, smart_card);
        byte DP [] = Algorithm.xor(Algorithm.hash(Algorithm.concat(ID_i.getBytes(), P_i.getBytes())), b1);  //DP = h(ID_i || P_i) XOR b1
        smart_card.DP = DP;
        smart_card.bbi = bb_i;
    }
        
    public boolean user_login(String ID_i_star , String P_i_star , String SID_m) throws Exception
    {
        byte b1_star [] = Algorithm.xor(smart_card.DP, Algorithm.hash(Algorithm.concat(ID_i_star.getBytes(), P_i_star.getBytes())));           //b1* = DP XOR h(ID* || Pi*)
        byte Ai_star [] = Algorithm.hash(Algorithm.concat(P_i_star.getBytes(), b1_star));                       // Ai* = h(Pi* || b1*)
        byte b2_star [] = Algorithm.xor(smart_card.bbi, Ai_star);                                               // b2* = bbi XOR Ai*
        byte PID_i_star [] = Algorithm.hash(Algorithm.concat(ID_i_star.getBytes(), b2_star));                   // PIDi* = h(IDi* || b2*)
        byte Ci_star [] = Algorithm.hash(Algorithm.concat(Ai_star, PID_i_star));                                // Ci* = h(Ai* || PIDi*)
        
        if (!(Algorithm.are_equal(Ci_star, smart_card.Ci)))
        {
            throw new Exception("password or user id is wrong");
        }
        
        SecureRandom random = new SecureRandom();
        byte Ni [] = new byte[16]; 
        random.nextBytes(Ni);                                           // create 128 bit random number and store it in N
        byte TSi [];
        byte Di [] = Algorithm.xor(smart_card.Ei, Ai_star);             // Di = Ei XOR Ai
        byte value [] = Algorithm.concat(PID_i_star, SID_m.getBytes());
        value = Algorithm.concat(value, Ni);
        TSi=Algorithm.get_timestamp();
        value = Algorithm.concat(value, Di);                            // add time stamp
        value = Algorithm.concat(value, TSi);                           // PROBLEM
        byte Gi [] = Algorithm.hash(value);                             // Gi = h(PIDi || SIDm || Ni || TSi || Di)
        //byte[] Gi = Algorithm.hash(Algorithm.concat(PIDi, Algorithm.concat(SIDm_star, Algorithm.concat(Ni_star, Algorithm.concat(Di, TSi)))));       // Gi* = h(PIDi || SIDm* || Ni* || Di || TSi)
        byte Fi [] = Algorithm.xor(Di , Ni);                            // Fi = Di XOR Ni
        byte Zi [] = Algorithm.xor(SID_m.getBytes(), Algorithm.hash(Algorithm.concat(Di, Ni)));                 // Zi = SIDm XOR h(Di || Ni)
        
        
        // Gi, Fi, Zi, PIDi, TSi      are login message
        
        
        byte[][] values = new byte[2][];
        try {
            Cloud_Server cloud_server = Algorithm.return_cloud_server(SID_m);
            values = cloud_server.authentication(Gi, Fi, Zi, PID_i_star, TSi);
        } catch (Exception e) {
            throw e;
        }
        
        byte[] Pcs = values[0];
        byte[] Qcs = values[1];
        byte[] Li = Algorithm.hash(Algorithm.concat(Ni, Di));                   // Li = h(Ni || Di)
        byte[] Nm_xor_Ncs = Algorithm.xor(Pcs, Li);                             // Nm xor Ncs = Pcs xor Li
        byte[] SKi = Algorithm.hash(Algorithm.xor(Nm_xor_Ncs, Ni));             // SKi = h(Nm xor Ncs xor Ni)
        byte[] Qcs_star = Algorithm.hash(Algorithm.concat(Nm_xor_Ncs, SKi));    // Qcs* = h((Nm xor Ncs) || SKi)
        
        if (!(Algorithm.are_equal(Qcs, Qcs_star)))
        {
            throw new Exception("Qcs* != Qcs");
        }
        
        return true;
    }
}
