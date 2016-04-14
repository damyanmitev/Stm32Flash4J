package stm32flash4j;

import gnu.getopt.Getopt;
import stm32flash4j.lib.IntPtr;
import stm32flash4j.lib.Stm32;
import stm32flash4j.lib.Stm32.*;

import java.io.PrintStream;
import static stm32flash4j.Main.actions.*;
import static stm32flash4j.lib.Stm32.*;
import static stm32flash4j.lib.Stm32.stderr;
import static stm32flash4j.lib.Stm32.stm32_err_t.*;
import static stm32flash4j.lib.Stm32.port_err_t.*;
import static stm32flash4j.lib.Stm32.serial_bits_t.*;
import static stm32flash4j.lib.Stm32.serial_parity_t.*;
import static stm32flash4j.lib.Stm32.serial_baud_t.*;
import static stm32flash4j.lib.Stm32.serial_stopbit_t.*;
import static stm32flash4j.lib.Stm32.parser_err_t.*;

public class Main {

//    public static void main(String[] args) {
//        System.out.println("Hello World!");
//    }


    public static final String NAME = "Stm32Flash4J";
    public static final String VERSION = "0.5";

/* device globals */
//    Stm32.stm32_t		*stm		= NULL;
    public static Stm32.stm32_t stm;

    public static Object p_st		= null;
    public static parser_t	parser		= null;

    /* settings */
    public static port_options port_opts = new port_options();
//    {
//        .device			= NULL,
//        .baudRate		= SERIAL_BAUD_57600,
//        .serial_mode		= "8e1",
//        .bus_addr		= 0,
//        .rx_frame_max		= STM32_MAX_RX_FRAME,
//        .tx_frame_max		= STM32_MAX_TX_FRAME,
//    };

    public static enum actions {
        ACT_NONE,
        ACT_READ,
        ACT_WRITE,
        ACT_WRITE_UNPROTECT,
        ACT_READ_PROTECT,
        ACT_READ_UNPROTECT,
        ACT_ERASE_ONLY,
        ACT_CRC
    };

    public static actions	action		= ACT_NONE;
    public static int		npages		= 0;
    public static int             spage           = 0;
    public static boolean             no_erase        = false;
    public static boolean		verify		= false;
    public static int		retry		= 10;
    public static boolean		exec_flag	= false;
    public static int	execute		= 0;
    public static boolean		init_flag	= true;
    public static boolean		force_binary	= false;
    public static boolean		reset_flag	= false;
    public static String filename;
    public static String gpio_seq	= null;
    public static int	start_addr	= 0;
    public static int	readwrite_len	= 0;

    public static String action2str(actions act)
    {
        switch (act) {
            case ACT_READ:
                return "memory read";
            case ACT_WRITE:
                return "memory write";
            case ACT_WRITE_UNPROTECT:
                return "write unprotect";
            case ACT_READ_PROTECT:
                return "read protect";
            case ACT_READ_UNPROTECT:
                return "read unprotect";
            case ACT_ERASE_ONLY:
                return "flash erase";
            case ACT_CRC:
                return "memory crc";
            default:
                return "";
        }
    }

    public static PrintStream diag = System.out;
    public static PrintStream stderr = System.err;
    public static PrintStream stdout = System.out;

    static void err_multi_action(actions newAction)
    {
        //fprintf(stderr,
        stderr.printf(
                "ERROR: Invalid options !\n" +
                "\tCan't execute \"%s\" and \"%s\" at the same time.\n",
                action2str(action), action2str(newAction));
    }

    public static port_interface port_open(port_options ops)//, port_interface outport)
    {
//        int ret;
//        static struct port_interface **port;
//
//        for (port = ports; *port; port++) {
//        ret = (*port)->open(*port, ops);
//        if (ret == PORT_ERR_NODEV)
//            continue;
//        if (ret == PORT_ERR_OK)
//            break;
//        fprintf(stderr, "Error probing interface \"%s\"\n",
//                (*port)->name);
//    }
//        if (*port == NULL) {
//        fprintf(stderr, "Cannot handle device \"%s\"\n",
//                ops->device);
//        return PORT_ERR_UNKNOWN;
//    }
//
//        *outport = *port;
//        return PORT_ERR_OK;

        port_interface port = new NetworkPort();
        port_err_t ret = port.open(ops);
        if (ret == PORT_ERR_OK)
            return port;
        return null;
    }


    public static void main(String[] argv){
//    int main(int argc, char* argv[]) {
        int argc = argv.length;


        port_interface port = null;
        int ret = 1;
        Stm32.stm32_err_t s_err;
        parser_err_t perr = PARSER_ERR_OK;



        diag.printf(NAME + " " + VERSION + "\n\n");
        diag.printf("http://stm32flash.sourceforge.net/\n\n");
        if (parse_options(argc, argv) != false)
        goto_close(port, ret);

        if ((action == ACT_READ) && filename.charAt(0) == '-') {
            diag = stderr;
        }

        if (action == ACT_WRITE) {
		/* first try hex */
            if (!force_binary) {
                parser = new PARSER_HEX();
                p_st = parser.init();
                if (!(p_st != null)) {
                    stderr.printf("%s Parser failed to initialize\n",parser.name);
                    goto_close(port, ret);
                }
            }

            if (force_binary || (perr =parser.open(p_st, filename, false)) != PARSER_ERR_OK) {
                if (force_binary || perr == PARSER_ERR_INVALID_FILE) {
                    if (!force_binary) {
                       parser.close(p_st);
                        p_st = null;
                    }

				/* now try binary */
                    parser = new PARSER_BINARY();
                    p_st =parser.init();
                    if (!(p_st != null)) {
                        stderr.printf("%s Parser failed to initialize\n",parser.name);
                        goto_close(port, ret);
                    }
                    perr =parser.open(p_st, filename, false);
                }

			/* if still have an error, fail */
                if (perr != PARSER_ERR_OK) {
                    stderr.printf("%s ERROR: %s\n",parser.name, parser_errstr(perr));
                    if (perr == PARSER_ERR_SYSTEM) perror(filename);
                    goto_close(port, ret);
                }
            }

            diag.printf("Using Parser : %s\n",parser.name);
        } else {
            parser = new PARSER_BINARY();
            p_st =parser.init();
            if (!(p_st != null)) {
                stderr.printf("%s Parser failed to initialize\n",parser.name);
                goto_close(port, ret);
            }
        }

        if ((port = port_open(port_opts)) == null) {
            stderr.printf("Failed to open port: %s\n", port_opts.device);
            goto_close(port, ret);
        }

        diag.printf("Interface %s: %s\n", port.name, port.get_cfg_str());
        if (init_flag && init_bl_entry(port, gpio_seq) == false)
        goto_close(port, ret);
        stm = Stm32.stm32_init(port, init_flag);
        if (!(stm != null))
        goto_close(port, ret);

        diag.printf("Version      : 0x%02x\n", stm.bl_version);
        if ((port.flags & PORT_GVR_ETX) != 0) {
            diag.printf("Option 1     : 0x%02x\n", stm.option1);
            diag.printf("Option 2     : 0x%02x\n", stm.option2);
        }
        diag.printf("Device ID    : 0x%04x (%s)\n", stm.pid, stm.dev.name);
        diag.printf("- RAM        : %dKiB  (%db reserved by bootloader)\n", (stm.dev.ram_end - 0x20000000) / 1024, stm.dev.ram_start - 0x20000000);
        diag.printf("- Flash      : %dKiB (size first sector: %dx%d)\n", (stm.dev.fl_end - stm.dev.fl_start ) / 1024, stm.dev.fl_pps, stm.dev.fl_ps[0]);
        diag.printf("- Option RAM : %db\n", stm.dev.opt_end - stm.dev.opt_start + 1);
        diag.printf("- System RAM : %dKiB\n", (stm.dev.mem_end - stm.dev.mem_start) / 1024);

        byte		buffer[] = new byte[256];
        int	addr, start, end;
        IntPtr	len = new IntPtr(0);
        int		failed = 0;
        int		first_page, num_pages;

	/*
	 * Cleanup addresses:
	 *
	 * Starting from options
	 *	start_addr, readwrite_len, spage, npages
	 * and using device memory size, compute
	 *	start, end, first_page, num_pages
	 */
        if (start_addr != 0 || readwrite_len != 0) {
            start = start_addr;

            if (is_addr_in_flash(stm, start))
                end = stm.dev.fl_end;
            else {
                no_erase = true;
                if (is_addr_in_ram(stm, start))
                    end = stm.dev.ram_end;
                else
                    end = start + 4;//sizeof(int);
            }

            if (readwrite_len != 0 && (end > start + readwrite_len))
                end = start + readwrite_len;

            first_page = flash_addr_to_page_floor(stm, start);
            if (!(first_page != 0) && end == stm.dev.fl_end)
                num_pages = STM32_MASS_ERASE;
            else
                num_pages = flash_addr_to_page_ceil(stm, end) - first_page;
        } else if (!(spage != 0) && !(npages != 0)) {
            start = stm.dev.fl_start;
            end = stm.dev.fl_end;
            first_page = 0;
            num_pages = STM32_MASS_ERASE;
        } else {
            first_page = spage;
            start = flash_page_to_addr(stm, first_page);
            if (start > stm.dev.fl_end) {
                stderr.printf("Address range exceeds flash size.\n");
                goto_close(port, ret);
            }

            if (npages != 0) {
                num_pages = npages;
                end = flash_page_to_addr(stm, first_page + num_pages);
                if (end > stm.dev.fl_end)
                    end = stm.dev.fl_end;
            } else {
                end = stm.dev.fl_end;
                num_pages = flash_addr_to_page_ceil(stm, end) - first_page;
            }

            if (!(first_page!=0) && end == stm.dev.fl_end)
                num_pages = STM32_MASS_ERASE;
        }

        if (action == ACT_READ) {
            int max_len = port_opts.rx_frame_max;

            diag.printf("Memory read\n");

            perr =parser.open(p_st, filename, true);
            if (perr != PARSER_ERR_OK) {
                stderr.printf("%s ERROR: %s\n",parser.name, parser_errstr(perr));
                if (perr == PARSER_ERR_SYSTEM)
                    perror(filename);
                goto_close(port, ret);
            }

            diag.flush();
            addr = start;
            while(addr < end) {
                int left	= end - addr;
                len.value		= max_len > left ? left : max_len;
                s_err = stm32_read_memory(stm, addr, buffer, len.value, 0);
                if (s_err != STM32_ERR_OK) {
                    stderr.printf("Failed to read memory at address 0x%08x, target write-protected?\n", addr);
                    goto_close(port, ret);
                }
                if (parser.write(p_st, buffer, len.value) != PARSER_ERR_OK)
                {
                    stderr.printf("Failed to write data to file\n");
                    goto_close(port, ret);
                }
                addr += len.value;

                diag.printf(
                        "\rRead address 0x%08x (%.2f%%) ",
                        addr,
                        (100.0f / (float)(end - start)) * (float)(addr - start)
                );
                diag.flush();
            }
            diag.printf(	"Done.\n");
            ret = 0;
            goto_close(port, ret);
        } else if (action == ACT_READ_PROTECT) {
            stdout.printf("Read-Protecting flash\n");
		/* the device automatically performs a reset after the sending the ACK */
            reset_flag = false;
            stm32_readprot_memory(stm);
            stdout.printf(	"Done.\n");
        } else if (action == ACT_READ_UNPROTECT) {
            stdout.printf("Read-UnProtecting flash\n");
		/* the device automatically performs a reset after the sending the ACK */
            reset_flag = false;
            stm32_runprot_memory(stm);
            stdout.printf(	"Done.\n");
        } else if (action == ACT_ERASE_ONLY) {
            ret = 0;
            stdout.printf("Erasing flash\n");

            if (num_pages != STM32_MASS_ERASE &&
                    (start != flash_page_to_addr(stm, first_page)
                            || end != flash_page_to_addr(stm, first_page + num_pages))) {
                stderr.printf("Specified start & length are invalid (must be page aligned)\n");
                ret = 1;
                goto_close(port, ret);
            }

            s_err = stm32_erase_memory(stm, first_page, num_pages);
            if (s_err != STM32_ERR_OK) {
                stderr.printf("Failed to erase memory\n");
                ret = 1;
                goto_close(port, ret);
            }
        } else if (action == ACT_WRITE_UNPROTECT) {
            diag.printf("Write-unprotecting flash\n");
		/* the device automatically performs a reset after the sending the ACK */
            reset_flag = false;
            stm32_wunprot_memory(stm);
            diag.printf(	"Done.\n");

        } else if (action == ACT_WRITE) {
            diag.printf("Write to memory\n");

            int 	offset = 0;
            int r;
            int size;
            int max_wlen, max_rlen;

            max_wlen = port_opts.tx_frame_max - 2;	/* skip len and crc */
            max_wlen &= ~3;	/* 32 bit aligned */

            max_rlen = port_opts.rx_frame_max;
            max_rlen = max_rlen < max_wlen ? max_rlen : max_wlen;

		/* Assume data from stdin is whole device */
            if (filename.charAt(0) == '-' && filename.length() == 1)//filename[1] == '\0')
                size = end - start;
            else
                size =parser.size(p_st);

            // TODO: It is possible to write to non-page boundaries, by reading out flash
            //       from partial pages and combining with the input data
            // if ((start % stm.dev.fl_ps[i]) != 0 || (end % stm.dev.fl_ps[i]) != 0) {
            //	stderr.printf("Specified start & length are invalid (must be page aligned)\n");
            //	goto_close(port, ret);
            // }

            // TODO: If writes are not page aligned, we should probably read out existing flash
            //       contents first, so it can be preserved and combined with new data
            if (!no_erase && num_pages != 0) {
                diag.printf("Erasing memory\n");
                s_err = stm32_erase_memory(stm, first_page, num_pages);
                if (s_err != STM32_ERR_OK) {
                    stderr.printf("Failed to erase memory\n");
                    goto_close(port, ret);
                }
            }

            //diag.flush();
            diag.flush();
            addr = start;
            while(addr < end && offset < size) {
                int left	= end - addr;
                len.value		= max_wlen > left ? left : max_wlen;
                len.value		= len.value > size - offset ? size - offset : len.value;

                if (parser.read(p_st, buffer, len) != PARSER_ERR_OK)
                goto_close(port, ret);

                if (len.value == 0) {
                    if (filename.charAt(0) == '-') {
                        break;
                    } else {
                        stderr.printf("Failed to read input file\n");
                        goto_close(port, ret);
                    }
                }

                again:
                do{
                s_err = stm32_write_memory(stm, addr, buffer, len.value, 0);
                if (s_err != STM32_ERR_OK) {
                    stderr.printf("Failed to write memory at address 0x%08x\n", addr);
                    goto_close(port, ret);
                }

                if (verify) {
                    byte compare[] = new byte[len.value];
                    int offset1, rlen;

                    offset1 = 0;
                    while (offset1 < len.value) {
                        rlen = len.value - offset1;
                        rlen = rlen < max_rlen ? rlen : max_rlen;
                        s_err = stm32_read_memory(stm, addr + offset1, compare, rlen, offset1);
                        if (s_err != STM32_ERR_OK) {
                            stderr.printf("Failed to read memory at address 0x%08x\n", addr + offset1);
                            goto_close(port, ret);
                        }
                        offset1 += rlen;
                    }

                    for(r = 0; r < len.value; ++r)
                        if (buffer[r] != compare[r]) {
                            if (failed == retry) {
                                stderr.printf("Failed to verify at address 0x%08x, expected 0x%02x and found 0x%02x\n",
                                        (int)(addr + r),
                                        buffer [r],
                                        compare[r]
                                );
                                goto_close(port, ret);
                            }
                            ++failed;
                            //goto again;
                            continue again;
                        }

                    failed = 0;
                }
                } while (failed != 0);

                addr	+= len.value;
                offset	+= len.value;

                diag.printf(
                        "\rWrote %saddress 0x%08x (%.2f%%) ",
                        verify ? "and verified " : "",
                        addr,
                        (100.0f / size) * offset
                );
                diag.flush();

            }

            diag.printf(	"Done.\n");
            ret = 0;
            goto_close(port, ret);
        } else if (action == ACT_CRC) {
            IntPtr crc_val = new IntPtr(0);

            diag.printf("CRC computation\n");

            s_err = stm32_crc_wrapper(stm, start, end - start, crc_val);
            if (s_err != STM32_ERR_OK) {
                stderr.printf("Failed to read CRC\n");
                goto_close(port, ret);
            }
            diag.printf("CRC(0x%08x-0x%08x) = 0x%08x\n", start, end,
                    crc_val.value);
            ret = 0;
            goto_close(port, ret);
        } else
            ret = 0;

        goto_close(port, ret);
//        close:
//        if (stm != null && exec_flag && ret == 0) {
//            if (execute == 0)
//                execute = stm.dev.fl_start;
//
//            diag.printf("\nStarting execution at address 0x%08x... ", execute);
//            diag.flush();
//            if (stm32_go(stm, execute) == STM32_ERR_OK) {
//                reset_flag = false;
//                diag.printf("done.\n");
//            } else
//                diag.printf("failed.\n");
//        }
//
//        if (stm != null && reset_flag) {
//            diag.printf("\nResetting device... ");
//            diag.flush();
//            if (init_bl_exit(stm, port, gpio_seq))
//                diag.printf("done.\n");
//            else	diag.printf("failed.\n");
//        }
//
//        if (p_st != null )parser.close(p_st);
//        if (stm != null) stm32_close  (stm);
//        if (port != null)
//            port.close();
//
//        diag.printf("\n");
//        System.exit(ret);
//        //return ret;
    }

    private static void perror(String filename) {
        stderr.printf("System error in file %s", filename);
    }

    public static void goto_close(port_interface port, int ret) {
        close:
        if (stm != null && exec_flag && ret == 0) {
            if (execute == 0)
                execute = stm.dev.fl_start;

            diag.printf("\nStarting execution at address 0x%08x... ", execute);
            diag.flush();
            if (stm32_go(stm, execute) == STM32_ERR_OK) {
                reset_flag = false;
                diag.printf("done.\n");
            } else
                diag.printf("failed.\n");
        }

        if (stm != null && reset_flag) {
            diag.printf("\nResetting device... ");
            diag.flush();
            if (init_bl_exit(stm, port, gpio_seq))
                diag.printf("done.\n");
            else	diag.printf("failed.\n");
        }

        if (p_st != null )parser.close(p_st);
        if (stm != null) stm32_close  (stm);
        if (port != null)
            port.close();

        diag.printf("\n");
        System.exit(ret);
        //return ret;

    }

    public static int strtoul(String s) {
        if (s == null || s.length() == 0)
            return 0;
        try {
            if (s.startsWith("0x") || s.startsWith("0X"))
                return Integer.parseUnsignedInt(s.substring(2), 16);
            if (s.startsWith("0o") || s.startsWith("0O"))
                return Integer.parseUnsignedInt(s.substring(2), 8);
            if (s.startsWith("0b") || s.startsWith("0B"))
                return Integer.parseUnsignedInt(s.substring(2), 2);
            if (s.startsWith("0"))
                return Integer.parseUnsignedInt(s.substring(1), 8);

            return Integer.parseUnsignedInt(s);
        } catch (Exception x) {
            return 0;
        }
    }


    public static boolean parse_options(int argc, String argv[])
    {
        Getopt g = new Getopt(NAME, argv, "a:b:m:r:w:e:vn:g:jkfcChuos:S:F:i:Rp:");
        int c;
//        String pLen;

        //while ((c = getopt(argc, argv, "a:b:m:r:w:e:vn:g:jkfcChuos:S:F:i:R")) != -1) {
        while ((c = g.getopt()) != -1) {
            switch(c) {
                case 'a':
                    port_opts.bus_addr = strtoul(g.getOptarg());
                    break;

                case 'b':
                    port_opts.baudRate = serial_get_baud(strtoul(g.getOptarg()));
                    if (port_opts.baudRate == SERIAL_BAUD_INVALID) {
                        //serial_baud_t baudrate;
                        stderr.printf(	"Invalid baud rate, valid options are:\n");
                        //for (baudrate = SERIAL_BAUD_1200; baudrate != SERIAL_BAUD_INVALID; ++baudrate)
                        for (serial_baud_t baudrate : serial_baud_t.values())
                            stderr.printf(" %d\n", serial_get_baud_int(baudrate));
                        return true;
                    }
                    break;

                case 'm':
                    if (g.getOptarg().length() != 3
                            || serial_get_bits(g.getOptarg()) == SERIAL_BITS_INVALID
                            || serial_get_parity(g.getOptarg()) == SERIAL_PARITY_INVALID
                            || serial_get_stopbit(g.getOptarg()) == SERIAL_STOPBIT_INVALID) {
                        stderr.printf("Invalid serial mode\n");
                        return true;
                    }
                    port_opts.serial_mode = g.getOptarg();
                    break;

                case 'r':
                case 'w':
                    if (action != ACT_NONE) {
                        err_multi_action((c == 'r') ? ACT_READ : ACT_WRITE);
                        return true;
                    }
                    action = (c == 'r') ? ACT_READ : ACT_WRITE;
                    filename = g.getOptarg();
                    if (filename.charAt(0) == '-') {
                        force_binary = true;
                    }
                    break;
                case 'e':
                    if (readwrite_len != 0 || start_addr != 0) {
                        stderr.printf("ERROR: Invalid options, can't specify start page / num pages and start address/length\n");
                        return true;
                    }
                    npages = strtoul(g.getOptarg());
                    if (npages > 0xFF || npages < 0) {
                        stderr.printf("ERROR: You need to specify a page count between 0 and 255");
                        return true;
                    }
                    if (!(npages != 0))
                        no_erase = true;
                    break;
                case 'u':
                    if (action != ACT_NONE) {
                        err_multi_action(ACT_WRITE_UNPROTECT);
                        return true;
                    }
                    action = ACT_WRITE_UNPROTECT;
                    break;

                case 'j':
                    if (action != ACT_NONE) {
                        err_multi_action(ACT_READ_PROTECT);
                        return true;
                    }
                    action = ACT_READ_PROTECT;
                    break;

                case 'k':
                    if (action != ACT_NONE) {
                        err_multi_action(ACT_READ_UNPROTECT);
                        return true;
                    }
                    action = ACT_READ_UNPROTECT;
                    break;

                case 'o':
                    if (action != ACT_NONE) {
                        err_multi_action(ACT_ERASE_ONLY);
                        return true;
                    }
                    action = ACT_ERASE_ONLY;
                    break;

                case 'v':
                    verify = true;
                    break;

                case 'n':
                    retry = strtoul(g.getOptarg());
                    break;

                case 'g':
                    exec_flag = true;
                    execute   = strtoul(g.getOptarg());
                    if (execute % 4 != 0) {
                        stderr.printf("ERROR: Execution address must be word-aligned\n");
                        return true;
                    }
                    break;
                case 's':
                    if (readwrite_len != 0 || start_addr != 0) {
                        stderr.printf("ERROR: Invalid options, can't specify start page / num pages and start address/length\n");
                        return true;
                    }
                    spage    = strtoul(g.getOptarg());
                    break;
                case 'S':
                    if (spage != 0 || npages != 0) {
                        stderr.printf("ERROR: Invalid options, can't specify start page / num pages and start address/length\n");
                        return true;
                    } else {
                        String multiopts[] = g.getOptarg().split(":");
                        start_addr = strtoul(multiopts[0]);
                        if (multiopts.length > 1) {
                            readwrite_len = strtoul(multiopts[1]);
                            if (readwrite_len == 0) {
                                stderr.printf("ERROR: Invalid options, can't specify zero length\n");
                                return true;
                            }
                        }
                    }
                    break;
                case 'F':
                    String multiopts[] = g.getOptarg().split(":");
                    port_opts.rx_frame_max = strtoul(multiopts[0]);
                    if (multiopts.length > 1) {
                        port_opts.tx_frame_max = strtoul(multiopts[1]);
                    }
                    if (port_opts.rx_frame_max < 0
                            || port_opts.tx_frame_max < 0) {
                        stderr.printf("ERROR: Invalid negative value for option -F\n");
                        return true;
                    }
                    if (port_opts.rx_frame_max == 0)
                        port_opts.rx_frame_max = STM32_MAX_RX_FRAME;
                    if (port_opts.tx_frame_max == 0)
                        port_opts.tx_frame_max = STM32_MAX_TX_FRAME;
                    if (port_opts.rx_frame_max < 20
                            || port_opts.tx_frame_max < 6) {
                        stderr.printf("ERROR: current code cannot work with small frames.\n");
                        stderr.printf("min(RX) = 20, min(TX) = 6\n");
                        return true;
                    }
                    if (port_opts.rx_frame_max > STM32_MAX_RX_FRAME) {
                        stderr.printf("WARNING: Ignore RX length in option -F\n");
                        port_opts.rx_frame_max = STM32_MAX_RX_FRAME;
                    }
                    if (port_opts.tx_frame_max > STM32_MAX_TX_FRAME) {
                        stderr.printf("WARNING: Ignore TX length in option -F\n");
                        port_opts.tx_frame_max = STM32_MAX_TX_FRAME;
                    }
                    break;
                case 'f':
                    force_binary = true;
                    break;

                case 'c':
                    init_flag = false;
                    break;

                case 'h':
                    show_help(NAME);
                    System.exit(0);

                case 'i':
                    gpio_seq = g.getOptarg();
                    break;

                case 'R':
                    reset_flag = true;
                    break;

                case 'C':
                    if (action != ACT_NONE) {
                        err_multi_action(ACT_CRC);
                        return true;
                    }
                    action = ACT_CRC;
                    break;

                case 'p':
                    port_opts.port = strtoul(g.getOptarg());
                    if (port_opts.port <= 0 || port_opts.port >= 65536) {
                        stderr.printf("ERROR: Invalid port number %s\n", port_opts.port);
                        return true;
                    }
                    break;

//                case 'q':
//                    multiopts = g.getOptarg().split(":");
//                    port_opts.host = multiopts[0];
//                    if (multiopts.length > 1) {
//                        port_opts.port = strtoul(multiopts[1]);
//                    } else
//                        port_opts.port = 23;
//                    break;
            }
        }

        for (c = g.getOptind(); c < argc; ++c) {
            if (port_opts.device != null) {
                stderr.printf("ERROR: Invalid parameter specified\n");
                show_help(NAME);
                return true;
            }
            port_opts.device = argv[c];
        }

        if (port_opts.device == null) {
            stderr.printf("ERROR: Device not specified\n");
            show_help(NAME);
            return true;
        }

        if ((action != ACT_WRITE) && verify) {
            stderr.printf("ERROR: Invalid usage, -v is only valid when writing\n");
            show_help(NAME);
            return true;
        }

        return false;
    }

    public static void show_help(String name) {
        stderr.printf(
                "Usage: %s [-bvngfhc] [-[rw] filename] [tty_device | i2c_device]\n" +
                "	-a bus_address	Bus address (e.g. for I2C port)\n" +
                "	-b rate		Baud rate (default 57600)\n" +
                "	-m mode		Serial port mode (default 8e1)\n" +
                "	-r filename	Read flash to file (or - stdout)\n" +
                "	-w filename	Write flash from file (or - stdout)\n" +
                "	-C		Compute CRC of flash content\n" +
                "	-u		Disable the flash write-protection\n" +
                "	-j		Enable the flash read-protection\n" +
                "	-k		Disable the flash read-protection\n" +
                "	-o		Erase only\n" +
                "	-e n		Only erase n pages before writing the flash\n" +
                "	-v		Verify writes\n" +
                "	-n count	Retry failed writes up to count times (default 10)\n" +
                "	-g address	Start execution at specified address (0 = flash start)\n" +
                "	-S address[:length]	Specify start address and optionally length for\n" +
                "	                   	read/write/erase operations\n" +
                "	-F RX_length[:TX_length]  Specify the max length of RX and TX frame\n" +
                "	-s start_page	Flash at specified page (0 = flash start)\n" +
                "	-f		Force binary parser\n" +
                "	-h		Show this help\n" +
                "	-c		Resume the connection (don't send initial INIT)\n" +
                "			*Baud rate must be kept the same as the first init*\n" +
                "			This is useful if the reset fails\n" +
                "	-i GPIO_string	GPIO sequence to enter/exit bootloader mode\n" +
                "			GPIO_string=[entry_seq][:[exit_seq]]\n" +
                "			sequence=[-]n[,sequence]\n" +
                "	-R		Reset device at exit.\n" +
                "	-q host[:port]	Specify host and port (default 23) for telnet connection\n" +
                "\n" +
                "Examples:\n" +
                "	Get device information:\n" +
                "		%s /dev/ttyS0\n" +
                "	  or:\n" +
                "		%s /dev/i2c-0\n" +
                "\n" +
                "	Write with verify and then start execution:\n" +
                "		%s -w filename -v -g 0x0 /dev/ttyS0\n" +
                "\n" +
                "	Read flash to file:\n" +
                "		%s -r filename /dev/ttyS0\n" +
                "\n" +
                "	Read 100 bytes of flash from 0x1000 to stdout:\n" +
                "		%s -r - -S 0x1000:100 /dev/ttyS0\n" +
                "\n" +
                "	Start execution:\n" +
                "		%s -g 0x0 /dev/ttyS0\n" +
                "\n" +
                "	GPIO sequence:\n" +
                "	- entry sequence: GPIO_3=low, GPIO_2=low, GPIO_2=high\n" +
                "	- exit sequence: GPIO_3=high, GPIO_2=low, GPIO_2=high\n" +
                "		%s -R -i -3,-2,2:3,-2,2 /dev/ttyS0\n",
                name,
                name,
                name,
                name,
                name,
                name,
                name,
                name
        );
    }
}
