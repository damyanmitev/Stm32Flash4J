package stm32flash4j;

import stm32flash4j.lib.Stm32;

import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketAddress;
import java.net.SocketTimeoutException;

/**
 * Created by Alfa on 13.4.2016 г..
 */
public class NetworkPort extends Stm32.port_interface {

    Socket client;


    @Override
    public Stm32.port_err_t open(Stm32.port_options ops) {
        try {
            //client = new Socket(ops.device, ops.port == 0 ? 23 : ops.port);
            client = new Socket();
            client.setSoTimeout(1000);
            client.connect(new InetSocketAddress(ops.device, ops.port == 0 ? 23 : ops.port), 1000);
        }catch (Exception x) {
            return Stm32.port_err_t.PORT_ERR_UNKNOWN;
        }
        return Stm32.port_err_t.PORT_ERR_OK;
    }

    @Override
    public Stm32.port_err_t close() {
        try {
            client.close();
        }catch (Exception x) {
            return Stm32.port_err_t.PORT_ERR_UNKNOWN;
        }
        return Stm32.port_err_t.PORT_ERR_OK;
    }

    @Override
    public Stm32.port_err_t read(byte[] buf, int nbyte) { //TODO PORT_ERR_TIMEDOUT
//        int r;
//        try {
//            r = client.getInputStream().read(buf, 0, nbyte);
//        }catch (SocketTimeoutException tx) {
//            return Stm32.port_err_t.PORT_ERR_TIMEDOUT;
//        }catch (Exception x) {
//            return Stm32.port_err_t.PORT_ERR_UNKNOWN;
//        }
//        if (r < nbyte)
//            return Stm32.port_err_t.PORT_ERR_UNKNOWN;//PORT_ERR_TIMEDOUT;
//        return Stm32.port_err_t.PORT_ERR_OK;
        return read(buf, nbyte, 0);
    }

    @Override
    public Stm32.port_err_t read(byte[] buf, int nbyte, int start) { //TODO PORT_ERR_TIMEDOUT
        int r;
        try {
            r = client.getInputStream().read(buf, start, nbyte);
        }catch (SocketTimeoutException tx) {
            return Stm32.port_err_t.PORT_ERR_TIMEDOUT;
        }catch (Exception x) {
            return Stm32.port_err_t.PORT_ERR_UNKNOWN;
        }
        if (r < nbyte)
            return Stm32.port_err_t.PORT_ERR_UNKNOWN;//PORT_ERR_TIMEDOUT;
        return Stm32.port_err_t.PORT_ERR_OK;
    }

    @Override
    public Stm32.port_err_t write(byte[] buf, int nbyte) {
        try {
            client.getOutputStream().write(buf, 0, nbyte);
        }catch (Exception x) {
            return Stm32.port_err_t.PORT_ERR_UNKNOWN;
        }
        return Stm32.port_err_t.PORT_ERR_OK;
    }

    @Override
    public Stm32.port_err_t write(byte[] buf, int nbyte, int start) {
        try {
            client.getOutputStream().write(buf, start, nbyte);
        }catch (Exception x) {
            return Stm32.port_err_t.PORT_ERR_UNKNOWN;
        }
        return Stm32.port_err_t.PORT_ERR_OK;
    }

    @Override
    public String get_cfg_str() {
        return client.toString();
    }
}
