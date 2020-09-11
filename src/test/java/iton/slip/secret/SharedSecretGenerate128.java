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

import iton.slip.secret.util.Utils;
import iton.slip.secret.words.Mnemonic;
import org.junit.*;
import org.spongycastle.util.encoders.Hex;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Collections;
import java.util.List;

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
    public void test() throws NoSuchAlgorithmException, SharedSecretException, InvalidKeyException {
        String s = "6f692adbf222c6edbd210be3053fa1f3";
        String[] m = new String[]{
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
        String ss = Hex.toHexString(shared.combine(new String[]{m[0], m[8]}, ""));
        System.out.println(ss);
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
