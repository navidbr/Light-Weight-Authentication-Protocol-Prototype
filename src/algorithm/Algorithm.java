/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package algorithm;


import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Scanner;

/**
 *
 * @author NAVID_University
 */
public class Algorithm {
    
    static User Arr_users [] = new User[1000];
    static String Arr_users_id [] = new String[1000];
    static int user_counter = 0;

    static Cloud_Server Arr_cloudservers [] = new Cloud_Server[1000];
    static int cloudserver_counter = 0;
    
    
    public static long program_run_time;            // for time stamp
    
    
    public static class Control_Server
    {
        private static byte X [] = new byte[16];
        public static byte Y [] = new byte[16];
        
        public static void control_server_initialize()
        {
            SecureRandom random = new SecureRandom();
            random.nextBytes(X);
            random.nextBytes(Y);
        }
        
        
        public static byte [] csr(byte d [] , String SID_m  ) // proccess of Cloud Server registeration
        {
            byte BS_m [];
            byte PSID_m [] = hash(concat(SID_m.getBytes(), d));
            BS_m = hash(concat(PSID_m, Control_Server.Y));
            return(BS_m);
        }
        
        public static Smart_Card ur(byte [] Ai , byte [] PID_i , Smart_Card sm) // proccess of User registeration
        {
            byte Ci [] = hash(concat(Ai, PID_i));                       //Ci = h(Ai || PID_i)
            byte Di [] = hash(concat(PID_i, Control_Server.X));         //Di = h(PID_i || X)
            byte Ei [] = xor(Di, Ai);                                   //Ei = Di XOR Ai
            
            sm.Ci = Ci;
            sm.Ei = Ei;
            // TODO         sm.h(0)=h(0)
            return(sm);
        }
        
        public static byte[][] authentication(byte [] Ji, byte [] Ki, byte [] PSIDm, byte [] Gi, byte [] Fi, byte [] Zi, byte [] PIDi, byte [] TSi, byte [] TSm) throws Exception
        {
            byte[] TScs = get_timestamp();
            if((byteArrayToInt(TScs)-byteArrayToInt(TSm)) > 1000)                       // delta t 
            {
                throw new Exception("cloud_server control_server time_out");            //TScs - TSm > delta t
            }
            
            byte[] Di = hash(concat(PIDi, X));                              // Di = h(PIDi || X)
            byte[] Ni_star = xor(Fi, Di);                                   // Ni* = Fi xor Di
            byte[] SIDm_star = xor(Zi, hash(concat(Di, Ni_star)));          // SIDm* = Zi xor h(Di || Ni*)
            byte[] Gi_star = hash(concat(PIDi, concat(SIDm_star, concat(Ni_star, concat(Di, TSi)))));       // Gi* = h(PIDi || SIDm* || Ni* || Di || TSi)
                                                        
            if (!(are_equal(Gi, Gi_star)))
            {
                throw new Exception("user is illegal");
            }
            
            byte[] BSm_star = hash(concat(PSIDm, Y));                                                       // BSm* = h(PSIDm || y)
            byte[] Nm_star = xor(BSm_star, Ji);                                                             // Nm* = BSm* xor Ji
            byte[] Ki_star = hash(concat(BSm_star, concat(Nm_star, concat(Gi, TSm))));                      // Ki* = h(BSm* || Nm* || Gi || TSm)
            
            if (!(are_equal(Ki_star, Ki)))
            {
                throw new Exception("cloud server is illegal");
            }
            
            byte[] Ncs = new byte[16];
            SecureRandom random = new SecureRandom();
            random.nextBytes(Ncs);                                                  // create 128 bit random number
            byte[] Pcs = xor(Nm_star, xor(Ncs, hash(concat(Ni_star, Di))));         // Pcs = Nm xor Ncs xor h(Ni || Di)     user and cloud server are legal   so  'Nm_star = Nm'  &  'Ni_star = Ni'
            byte[] Rcs = xor(Ni_star, xor(Ncs, hash(concat(BSm_star, Nm_star))));         // Rcs = Ni xor Ncs xor h(BSm* || Nm*)
            byte[] SKcs = hash(xor(Ni_star, xor(Nm_star, Ncs)));                          //SKcs => secret session key     SKcs = h(Ni || Nm || Ncs)
            byte[] Qcs = hash(concat(xor(Nm_star, Ncs), SKcs));                     // Qcs = h((Nm xor Ncs) || SKcs)
            byte[] Vcs = hash(concat(xor(Ni_star, Ncs), SKcs));                     // Vcs = h((Ni || Ncs) || SKcs)
                                        // PROBLEM
            
            byte[][] result = new byte[4][];
            result[0]=Pcs;
            result[1]=Rcs;
            result[2]=Qcs;
            result[3]=Vcs;
            
            return result;                                      // return Pcs, Rcs, Qcs, Vcs
        }
    }
    
    
    public static byte [] hash( byte[] value )
    {
        MessageDigest md = null;
        try {
            md = MessageDigest.getInstance("SHA-1");
        }
        catch(Exception e) {
            e.printStackTrace();
        } 
        byte [] result;
        result = md.digest(value);
        return result;
    }

    
    public static byte [] concat(byte [] value1 , byte [] value2)
    {
        int i1 = value1.length;
        int i2 = value2.length;
        byte[] result = new byte[i1+i2];
        int i=0;
        while(i<i1)
        {
            result[i] = value1[i];
            i++;
        }
        i=0;
        while(i<i2)
        {
            result[i+i1]=value2[i];
            i++;
        }
        return result;
    }
    

    public static byte [] xor(byte [] value1, byte [] value2)
    {
        int i1=value1.length;
        int i2=value2.length;
        byte result [];
        if(i1 > i2)
        {
            result = new byte[i1];
            int d = i1 - i2;
            for (int i = 0; i < d ; i++) {
                result[i] = value1[i];
            }
            for (int i = 0; i < i2; i++) {
                result[i+d] = (byte) (value1[i+d] ^ value2[i]);
            }
        }else
        {
            result = new byte[i2];
            int d = i2 - i1;
            for (int i = 0; i < d ; i++) {
                result[i] = value2[i];
            }
            for (int i = 0; i < i1; i++) {
                result[i+d] = (byte) (value2[i+d] ^ value1[i]);
            }
        }
        int newsize=result.length;
        while(result[0]==0)
        {
            newsize--;
            for(int i=0; i<((result.length)-1); i++)
            {
                result[i] = result[i+1];                        // 0 0 0 0 124 12 89 65 32 ...
            }
        }
        byte[] r=new byte[newsize];
        for(int i=0; i<newsize; i++)
        {
            r[i]=result[i];
        }
        return r;
    }
    
    
    public static byte [] get_timestamp()
    {
        int ts = (int) ((int) System.currentTimeMillis() - program_run_time);
        return new byte[] {(byte)(ts >>> 24), (byte)(ts >>> 16), (byte)(ts >>> 8), (byte)ts};
    }
    
    
    public static String tostring(byte[] value)
    {
        return (new String(value , StandardCharsets.UTF_8));
    }
    
    
    public static boolean are_equal(byte[] v1 , byte[] v2)
    {
//        byte[] v3;
//        if(v1.length>v2.length)
//        {
//            v3 = new byte[v2.length];
//            for( int i =0; i<v2.length; i++)
//            {
//                v3[i] = v1[i+(v1.length-v2.length)];
//            }
//            return((new String(v3,StandardCharsets.UTF_8).equals(new String(v2,StandardCharsets.UTF_8))));
//        }else
//        {
//            v3 = new byte[v1.length];
//            for( int i =0; i<v1.length; i++)
//            {
//                v3[i] = v2[i+(v2.length-v1.length)];
//            }
//            return((new String(v3,StandardCharsets.UTF_8).equals(new String(v1,StandardCharsets.UTF_8))));
//        }
        return((new String(v1,StandardCharsets.UTF_8).equals(new String(v2,StandardCharsets.UTF_8))));
    }
    
    
    public static void print(byte[] v)
    {
        for(int i=0; i<v.length; i++)
        {
            System.out.print(v[i]+" ");
        }
        System.out.println("");
    }
    
    
    public static int byteArrayToInt(byte[] b) 
    {
        int value = 0;
        for (int i = 0; i < 4; i++) {
            int shift = (4 - 1 - i) * 8;
            value += (b[i] & 0x000000FF) << shift;
        }
        return value;
    }
    
    
    public static Cloud_Server return_cloud_server(String SID_m) throws Exception
    {
        for (int i = 0; i < cloudserver_counter; i++) {
            if (Arr_cloudservers[i].SID_m.equals(SID_m)) {
                return Arr_cloudservers[i];
            }
        }
        throw new Exception("there is no such cloud server");
    }
    
    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) throws UnsupportedEncodingException {
        
        program_run_time = System.currentTimeMillis();
        
        boolean run = true;
        
        Control_Server.control_server_initialize();
        
//        User Arr_users [] = new User[1000];
//        String Arr_users_id [] = new String[1000];
//        int user_counter = 0;
//        
//        Cloud_Server Arr_cloudservers [] = new Cloud_Server[1000];
//        int cloudserver_counter = 0; 
        
        
        while (run)
        {
            System.out.flush();
            System.out.println("");
            System.out.println("");
            System.out.println("");
            System.out.println("");
            System.out.println("");
            System.out.println("");
            System.out.println("");
            System.out.println("What do you want to do?");
            System.out.println("");
            System.out.println("1. Register a new user");
            System.out.println("2. Register a new cloud server");
            System.out.println("3. Login user");
            System.out.println("4. List users");
            System.out.println("5. List Cloud Servers");
            System.out.println("6. Exit");
            System.out.println("");
            System.out.println("Please insert a number...");

            Scanner scanner = new Scanner(System.in);

            String input = scanner.nextLine();



            switch (input)
            {
                case "1":
                {
                    System.out.println("Please enter User ID");
                    String user_id = scanner.nextLine();
                    System.out.println("Please enter Password");
                    String password = scanner.nextLine();
                    User u = new User();
                    u.user_register(user_id, password);
                    Arr_users[user_counter] = u;
                    Arr_users_id[user_counter] = user_id;
                    user_counter++;

                    break;
                }
                case "2":
                {
                    System.out.println("Please enter Cloud Server ID");
                    String cs_id = scanner.nextLine();
                    Cloud_Server c = new Cloud_Server();
                    c.cloud_server_register(cs_id);
                    Arr_cloudservers[cloudserver_counter] = c;
                    cloudserver_counter++;
                    break;
                }
                case "3":
                {
                    System.out.println("Please enter User ID");
                    String u_id = scanner.nextLine();
                    System.out.println("Please enter Password");
                    String p = scanner.nextLine();
                    System.out.println("Please enter Cloud Server ID");
                    String csid = scanner.nextLine();

                    int i=0;
                    while(i < user_counter)
                    {
                        if (u_id.equals(Arr_users_id[i]))
                        {
                            try {
                                if(Arr_users[i].user_login(u_id, p, csid))
                                {
                                    System.out.println("");
                                    System.out.println("Login is ok");
                                    System.out.println("Press enter to continue ...");
                                    scanner.nextLine();
                                }
                            } catch (Exception e) {
                                System.out.println("");
                                System.out.println(e.toString());
                                System.out.println("");
                                System.out.println("Press enter to continue ...");
                                scanner.nextLine();
                            }
                            break;
                        }
                        else
                        {
                            if (i == (user_counter - 1))
                            {
                                System.out.println("");
                                System.out.println("There is no such username");
                                System.out.println("");
                                System.out.println("Press enter to continue ...");
                                scanner.nextLine();
                            }
                        }
                        i++;    
                    }
                    break;
                } 
                
                case "4":
                { 
                    System.out.println("");
                    System.out.println("");
                    for(int i = 0 ; i<user_counter; i++)
                    {
                        System.out.println(Arr_users_id[i]);
                        System.out.print("    smart_card.Ci  :: ");
                        print(Arr_users[i].smart_card.Ci);
                        System.out.print("    smart_card.DP  :: ");
                        print(Arr_users[i].smart_card.DP);
                        System.out.print("    smart_card.Ei  :: ");
                        print(Arr_users[i].smart_card.Ei);
                        System.out.print("    smart_card.bbi :: ");
                        print(Arr_users[i].smart_card.bbi);
                        System.out.println("");
                        
                    }
                    System.out.println("");
                    System.out.println("Press enter to continue ...");
                    scanner.nextLine();
                    break;
                }   
                
                case "5":
                {   
                    System.out.println("");
                    System.out.println("");
                    for(int i = 0 ; i<cloudserver_counter; i++)
                    {
                        System.out.println(Arr_cloudservers[i].SID_m);
                        System.out.print("    BS_m :: ");
                        print(Arr_cloudservers[i].BS_m);
                        System.out.print("    d    :: ");
                        print(Arr_cloudservers[i].d);
                        System.out.println("");
                    }
                    System.out.println("");
                    System.out.println("Press enter to continue ...");
                    scanner.nextLine();
                    break;
                }
                
                case "6":
                    run = false;
                    break;
            }
        }
    }
}
