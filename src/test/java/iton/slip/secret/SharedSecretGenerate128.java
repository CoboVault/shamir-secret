/*
 * The MIT License
 *
 * Copyright 2020 ITON Solutions.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package iton.slip.secret;

import iton.slip.secret.util.CombinationTest;
import iton.slip.secret.util.Crypto;
import iton.slip.secret.util.Utils;
import iton.slip.secret.words.Mnemonic;
import org.junit.*;
import org.spongycastle.util.encoders.Hex;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Collections;
import java.util.List;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

/**
 * @author Andrei
 */
public class SharedSecretGenerate128 {

    public SharedSecretGenerate128() {
    }

    @BeforeClass
    public static void setUpClass() {
    }

    @AfterClass
    public static void tearDownClass() {
    }

    @Before
    public void setUp() {
    }

    @After
    public void tearDown() {
    }

    @Test
    public void testGenerateRestore() throws SharedSecretException, NoSuchAlgorithmException, InvalidKeyException {
        byte iteration_exponent = 0;
        byte groups_threshold = 2;
        byte[] master_secret = new byte[16];
        Utils.randomBytes(master_secret);
        SharedSecret shared = new SharedSecret();
        List<String> mnemonics = shared.generate(master_secret, "", groups_threshold,
                Collections.nCopies(9, new Group(1, 1)),
                iteration_exponent);
        assertEquals(mnemonics.size(), 9);
        mnemonics.forEach(System.out::println);
        mnemonics.forEach(s -> {
            try {
                System.out.println(Mnemonic.INSTANCE.decode(s));
            } catch (SharedSecretException e) {
                e.printStackTrace();
            }
        });
    }

    @Test
    public void testCombination() throws NoSuchAlgorithmException, SharedSecretException, InvalidKeyException {
        String s = "6f692adbf222c6edbd210be3053fa1f3";
        String[] m = new String[] {
                "drove enlarge actress academic avoid clogs alien client result scandal cultural network physics failure legend tenant research involve cause together",
                "drove enlarge become academic dwarf tactics elevator playoff velvet triumph impulse loud surface velvet station evoke phrase fiction glimpse papa",
                "drove enlarge change academic crucial senior manual corner temple necklace width alien style aquatic emperor burden educate gross deal dress",
                "drove enlarge decorate academic bulb depend sharp phrase promise reaction perfect broken pickup promise best raspy freshman emphasis index jury",
                "drove enlarge educate academic adapt thumb junk olympic script kidney location airline strategy true ambition agency sharp spark husky ruin",
                "drove enlarge faint academic debut carpet duke believe lying fancy story bulb pencil envelope funding plastic spew username depend losing",
                "drove enlarge genre academic clogs amuse vampire method obtain cause failure obtain permit rapids sister writing depend salon gather bundle",
                "drove enlarge idle academic black vanish radar capital spray aunt august lips steady blimp nylon fatal daisy teaspoon chubby freshman",
                "drove enlarge legend academic benefit response woman else slush promise ladybug adjust tackle duration modern crazy briefing video ting deploy"
        };
        SharedSecret shared = new SharedSecret();
        List<int[]> combinations = new CombinationTest().generate(m.length,2);

        for (int[] combination : combinations) {
            byte[] data = shared.combine(new String[]{m[combination[0]], m[combination[1]]}, "");
            assertArrayEquals(data, Hex.decode(s));
        }
    }

    @Test
    public void aaa() throws NoSuchAlgorithmException, SharedSecretException, InvalidKeyException {
        String[] a = new String[]{
                "tactics cause academic acne august vanish blessing formal carbon axle crazy priest treat practice receiver exchange gather obesity loud forbid",
                "tactics cause academic agree dominant exhaust grownup woman racism pleasure breathe taste cinema brave loan improve burden network lend chest",
                "tactics cause academic amazing disease mother discuss galaxy relate fiction frost minister epidemic alcohol resident hybrid cover dwarf endorse burning",
                "tactics cause academic arcade argue costume erode warn bike unfold huge teacher library ranked mailman expand family dress elevator gasoline",
        };
        for (String aa : a) {
            Share share = Mnemonic.INSTANCE.decode(aa);
            System.out.println(share);
        }
        SharedSecret shared = new SharedSecret();
        byte[] data1 = shared.combine(new String[]{a[0],a[1],a[2]},"");
        System.out.println(Hex.toHexString(data1));


        byte[] data2 = Crypto.encrypt((short)28516,(byte)1, data1,"");
        byte[] data3 = Crypto.decrypt((short)28516,(byte)1, data2,"a");

        byte[] data = shared.combine(new String[]{a[0],a[1],a[2]},"a");
        System.out.println(Hex.toHexString(data3));
        System.out.println(Hex.toHexString(data));
    }

    @Test
    public void testCombineWithoutDecrypt() throws NoSuchAlgorithmException, SharedSecretException, InvalidKeyException {
        byte[] data = new byte[16];
        //satoshi costume academic acid activity presence wrote romantic threaten failure clothes guilt ranked mobile network justice adult security music replace
        //satoshi costume academic agency building bike wavy award retreat station sniff scene coal universe aquatic formal coastal provide wrap blimp
        List<String> shares = new SharedSecret().generateWithoutEncrypt(data,(byte) 1, Collections.singletonList(new Group(2,2)));
        for (String share : shares) {
            System.out.println(share);
        }
        Share share = Mnemonic.INSTANCE.decode("satoshi costume academic acid activity presence wrote romantic threaten failure clothes guilt ranked mobile network justice adult security music replace");
        System.out.println(share);
        byte[] seed = Crypto.decrypt((short)24997,(byte) 1,data,"");
        System.out.println(Hex.toHexString(seed));

        byte[] seed1 = Crypto.encrypt((short)24997,(byte) 1,seed,"");
        byte[] seed2 = Crypto.decrypt((short)24997,(byte) 1,seed1,"a");
        System.out.println(Hex.toHexString(seed2));

        byte[] result = new SharedSecret().combineWithoutDecrypt(shares.toArray(new String[0]));
        System.out.println(Hex.toHexString(result));
    }

    @Test
    public void testRestore1() throws SharedSecretException, NoSuchAlgorithmException, InvalidKeyException {

        String passphrase = "alcatraz";
        String secret = "cd87c628f1ef7747db8c19f9c906ce25";

        String[] mnemonics = new String[]{
                "biology enlarge deal romp chest beam pencil retreat desert ticket isolate clothes describe paper furl crucial involve funding welfare jury"
        };

        SharedSecret shared = new SharedSecret();
        byte[] master_secret = shared.combine(mnemonics, passphrase);
        String master = Hex.toHexString(master_secret);
        assertEquals(secret, master);
    }

    @Test
    public void testRestore2() throws SharedSecretException, NoSuchAlgorithmException, InvalidKeyException {

        String passphrase = "alcatraz";
        String secret = "cd87c628f1ef7747db8c19f9c906ce25";

        String[] mnemonics = new String[]{
                "biology enlarge academic scared canyon worthy spirit evoke blessing fatigue wisdom angel forget artist burning anatomy switch cradle welfare spit",
                "biology enlarge academic shadow divorce cleanup speak lungs maximum desert mayor spend ocean decorate prevent pulse force payment secret moment",
        };

        SharedSecret shared = new SharedSecret();
        byte[] master_secret = shared.combine(mnemonics, passphrase);
        String master = Hex.toHexString(master_secret);
        assertEquals(secret, master);
    }

    @Test
    public void testRestore3() throws SharedSecretException, NoSuchAlgorithmException, InvalidKeyException {

        String passphrase = "alcatraz";
        String secret = "cd87c628f1ef7747db8c19f9c906ce25";

        String[] mnemonics = new String[]{
                "biology enlarge away shaft blessing staff plastic laser require fraction texture welcome mixed reject trend email dilemma decent regular boring",
                "biology enlarge away round dream alpha manager company should liquid fangs always rebound suitable parking mansion flexible briefing costume beaver",
                "biology enlarge away scatter describe math glance gesture funding typical midst climate image raspy jacket hanger drift enjoy shadow focus",
        };

        SharedSecret shared = new SharedSecret();
        byte[] master_secret = shared.combine(mnemonics, passphrase);
        String master = Hex.toHexString(master_secret);
        assertEquals(secret, master);
    }
}
