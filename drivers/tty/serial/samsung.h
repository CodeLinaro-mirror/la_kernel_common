// SPDX-License-Identifier: GPL-2.0
#ifndef __SAMSUNG_H
#define __SAMSUNG_H

/*
 * Driver for Samsung SoC onboard UARTs.
 *
 * Ben Dooks, Copyright (c) 2003-2008 Simtec Electronics
 *	http://armlinux.simtec.co.uk/
*/

#include <linux/dmaengine.h>

struct s3c24xx_uart_info {
	char			*name;
	unsigned int		type;
	unsigned int		fifosize;
	unsigned long		rx_fifomask;
	unsigned long		rx_fifoshift;
	unsigned long		rx_fifofull;
	unsigned long		tx_fifomask;
	unsigned long		tx_fifoshift;
	unsigned long		tx_fifofull;
	unsigned int		def_clk_sel;
	unsigned long		num_clks;
	unsigned long		clksel_mask;
	unsigned long		clksel_shift;

	/* uart port features */

	unsigned int		has_divslot:1;

	/* uart controls */
	int (*reset_port)(struct uart_port *, struct s3c2410_uartcfg *);
};

struct s3c24xx_serial_drv_data {
	struct s3c24xx_uart_info	*info;
	struct s3c2410_uartcfg		*def_cfg;
	unsigned int			fifosize[CONFIG_SERIAL_SAMSUNG_UARTS];
};

struct s3c24xx_uart_dma {
	unsigned int			rx_chan_id;
	unsigned int			tx_chan_id;

	struct dma_slave_config		rx_conf;
	struct dma_slave_config		tx_conf;

	struct dma_chan			*rx_chan;
	struct dma_chan			*tx_chan;

	dma_addr_t			rx_addr;
	dma_addr_t			tx_addr;

	dma_cookie_t			rx_cookie;
	dma_cookie_t			tx_cookie;

	char				*rx_buf;

	dma_addr_t			tx_transfer_addr;

	size_t				rx_size;
	size_t				tx_size;

	struct dma_async_tx_descriptor	*tx_desc;
	struct dma_async_tx_descriptor	*rx_desc;

	int				tx_bytes_requested;
	int				rx_bytes_requested;
};

struct s3c24xx_uart_port {
	unsigned char			rx_claimed;
	unsigned char			tx_claimed;
	unsigned int			pm_level;
	unsigned long			baudclk_rate;
	unsigned int			min_dma_size;

	unsigned int			rx_irq;
	unsigned int			tx_irq;

	unsigned int			tx_in_progress;
	unsigned int			tx_mode;
	unsigned int			rx_mode;

	struct s3c24xx_uart_info	*info;
	struct clk			*clk;
	struct clk			*baudclk;
	struct uart_port		port;
	struct s3c24xx_serial_drv_data	*drv_data;

	/* reference to platform data */
	struct s3c2410_uartcfg		*cfg;

	struct s3c24xx_uart_dma		*dma;

#ifdef CONFIG_ARM_S3C24XX_CPUFREQ
	struct notifier_block		freq_transition;
#endif
};

/* conversion functions */

#define s3c24xx_dev_to_port(__dev) dev_get_drvdata(__dev)

/* register access controls */

#define portaddr(port, reg) ((port)->membase + (reg))
#define portaddrl(port, reg) \
	((unsigned long *)(unsigned long)((port)->membase + (reg)))

#define rd_regb(port, reg) (readb_relaxed(portaddr(port, reg)))
#define rd_regl(port, reg) (readl_relaxed(portaddr(port, reg)))

#define wr_regb(port, reg, val) writeb_relaxed(val, portaddr(port, reg))
#define wr_regl(port, reg, val) writel_relaxed(val, portaddr(port, reg))

/* Byte-order aware bit setting/clearing functions. */

static inline void s3c24xx_set_bit(struct uart_port *port, int idx,
				   unsigned int reg)
{
	unsigned long flags;
	u32 val;

	local_irq_save(flags);
	val = rd_regl(port, reg);
	val |= (1 << idx);
	wr_regl(port, reg, val);
	local_irq_restore(flags);
}

static inline void s3c24xx_clear_bit(struct uart_port *port, int idx,
				     unsigned int reg)
{
	unsigned long flags;
	u32 val;

	local_irq_save(flags);
	val = rd_regl(port, reg);
	val &= ~(1 << idx);
	wr_regl(port, reg, val);
	local_irq_restore(flags);
}

#if	defined(CONFIG_SERIAL_SAMSUNG_DEBUG) &&	\
	!defined(MODULE)

extern void printascii(const char *);

__printf(1, 2)
static void dbg(const char *fmt, ...)
{
	va_list va;
	char buff[256];

	va_start(va, fmt);
	vscnprintf(buff, sizeof(buff), fmt, va);
	va_end(va);

	printascii(buff);
}

#else
#define dbg(fmt, ...) do { if (0) no_printk(fmt, ##__VA_ARGS__); } while (0)
#endif

#if defined(CONFIG_ARCH_EXYNOS)
#define EXYNOS_COMMON_SERIAL_DRV_DATA				\
	.info = &(struct s3c24xx_uart_info) {			\
		.name		= "Samsung Exynos UART",	\
		.type		= PORT_S3C6400,			\
		.has_divslot	= 1,				\
		.rx_fifomask	= S5PV210_UFSTAT_RXMASK,	\
		.rx_fifoshift	= S5PV210_UFSTAT_RXSHIFT,	\
		.rx_fifofull	= S5PV210_UFSTAT_RXFULL,	\
		.tx_fifofull	= S5PV210_UFSTAT_TXFULL,	\
		.tx_fifomask	= S5PV210_UFSTAT_TXMASK,	\
		.tx_fifoshift	= S5PV210_UFSTAT_TXSHIFT,	\
		.def_clk_sel	= S3C2410_UCON_CLKSEL0,		\
		.num_clks	= 1,				\
		.clksel_mask	= 0,				\
		.clksel_shift	= 0,				\
	},							\
	.def_cfg = &(struct s3c2410_uartcfg) {			\
		.ucon		= S5PV210_UCON_DEFAULT,		\
		.ufcon		= S5PV210_UFCON_DEFAULT,	\
		.has_fracval	= 1,				\
	}							\

#endif

int s3c24xx_serial_get_ports(struct s3c24xx_uart_port **ourport, int index);
int s3c24xx_serial_init_port(struct s3c24xx_uart_port *ourport,
				    struct platform_device *platdev);
inline int s3c24xx_serial_cpufreq_register(struct s3c24xx_uart_port *port);
inline void s3c24xx_serial_cpufreq_deregister(struct s3c24xx_uart_port *port);
int s3c24xx_serial_unregister_port(struct platform_device *dev);
int s3c24xx_serial_suspend(struct device *dev);
int s3c24xx_serial_resume(struct device *dev);
int s3c24xx_serial_resume_noirq(struct device *dev);
#endif
