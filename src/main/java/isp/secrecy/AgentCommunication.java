package isp.secrecy;

import java.nio.charset.StandardCharsets;

import fri.isp.Agent;
import fri.isp.Environment;

/**
 * A communication channel is implemented with thread-safe blocking queue.
 * <p/>
 * Both agents are implemented by extending the Agents class,
 * creating anonymous class and overriding #execute().
 * <p/>
 * Both agents are started at the end of the main method definition below.
 */
public class AgentCommunication {
    public static void main(String[] args) {
        final Environment env = new Environment();

        env.add(new Agent("alice") {
            @Override
            public void task() {
                final byte[] payload = "Hi, Bob, this is Alice.".getBytes(StandardCharsets.UTF_8);
                // send message to recepient bob in byte array format -> serialization is always necessary
                send("bob", payload);
                final byte[] received = receive("bob");
                print("Got '%s', converted to string: '%s'", hex(received), new String(received));
            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() {
                send("alice", "Hey Alice, Bob here.".getBytes(StandardCharsets.UTF_8));
                print("Got '%s'", new String(receive("alice"), StandardCharsets.UTF_8));
            }
        });
        // task method of alice and bob runs at the same time
        env.connect("alice", "bob");
        env.start();
    }
}
